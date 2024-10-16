from typing import Any

import logging
import sys
import uuid

from rdflib import RDF, Graph, Literal, Namespace, URIRef

from .crypto_provider import CryptoProvider
from .data import DATAPRODUCT_METADATA

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


ODRL = Namespace("http://www.w3.org/ns/odrl/2/")
DCTERMS = Namespace("http://purl.org/dc/terms/")
DCAT = Namespace("http://www.w3.org/ns/dcat#")


def cut_string(text: str, max_length: int = 100) -> str:
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


# --------------------------------------------------------------------------------------


class UserContext:
    country: str

    def __init__(self, country: str):
        self.country = country


class AuthClient:
    """KERI Client"""

    aid: str
    user_context: UserContext

    def __init__(self, user_context: UserContext):
        self.aid = str(uuid.uuid4())
        self.user_context = user_context

    def get_aid(self) -> str:
        return self.aid

    def get_context(self) -> UserContext:
        return self.user_context


# --------------------------------------------------------------------------------------


class BaseValidator:
    def validate(self, constraint: dict[Any, Any], user_context: UserContext) -> bool:
        raise NotImplementedError("Subclasses must implement this method")


class CountryValidator(BaseValidator):
    def validate(self, constraint: Any, user_context: UserContext) -> bool:
        left_operand: URIRef = constraint.get(ODRL.leftOperand)
        operator: URIRef = constraint.get(ODRL.operator)
        right_operand: Literal = constraint.get(ODRL.rightOperand)

        if left_operand != ODRL.spatial:
            return True

        if operator != ODRL.eq:
            raise Exception(f"Operator {operator} is not supported")

        return (
            left_operand == ODRL.spatial
            and operator == ODRL.eq
            and right_operand == Literal(user_context.country)
        )


class DCAT3:
    def __init__(self, metadata: str):
        self.graph = Graph()
        self.graph.parse(data=metadata, format="json-ld")
        self.validators = [CountryValidator()]

    def validate_policy(self, user_context: UserContext) -> bool:
        for policy in self.graph.subjects(RDF.type, ODRL.Policy):
            for permission in self.graph.objects(policy, ODRL.permission):
                for constraint in self.graph.objects(permission, ODRL.constraint):
                    constraint_dict = {
                        ODRL.leftOperand: self.graph.value(
                            constraint, ODRL.leftOperand
                        ),
                        ODRL.operator: self.graph.value(constraint, ODRL.operator),
                        ODRL.rightOperand: self.graph.value(
                            constraint, ODRL.rightOperand
                        ),
                    }
                    for validator in self.validators:
                        if not validator.validate(constraint_dict, user_context):
                            return False
        return True

    def get_all_distribution_download_urls(self) -> list[str]:
        download_urls = []
        for distribution in self.graph.subjects(RDF.type, DCAT.Distribution):
            download_url = self.graph.value(
                subject=distribution, predicate=DCAT.downloadURL
            )
            if download_url:
                download_urls.append(str(download_url))
        return download_urls


# --------------------------------------------------------------------------------------


class ContractRequest:
    def __init__(
        self,
        dataproduct: "DataProduct",
        consumer: "DSConnector",
        consumer_signature: bytes,
    ):
        self.dataproduct = dataproduct
        self.consumer = consumer
        self.consumer_signature = consumer_signature

    def __str__(self):
        return (
            f"ContractRequest("
            f"dataproduct={self.dataproduct}, "
            f"consumer_aid={self.consumer.auth_client.get_aid()}, "
            f"consumer_signature={cut_string(self.consumer_signature.hex())})"
        )


class Contract(ContractRequest):
    def __init__(
        self,
        request: ContractRequest,
        provider: "DSConnector",
        provider_signature: bytes,
    ):
        super().__init__(
            dataproduct=request.dataproduct,
            consumer=request.consumer,
            consumer_signature=request.consumer_signature,
        )
        self.provider = provider
        self.provider_signature = provider_signature

    def __str__(self):
        return (
            f"Contract("
            f"dataproduct={self.dataproduct}, "
            f"consumer_aid={self.consumer.auth_client.get_aid()}, "
            f"consumer_signature={self.consumer_signature.hex()}, "
            f"provider_aid={self.provider.auth_client.get_aid()}, "
            f"provider_signature={cut_string(self.provider_signature.hex())})"
        )


# --------------------------------------------------------------------------------------


class DataProduct:
    def __init__(self, id: str, metadata: str):
        self.id = id
        self.metadata = metadata

    def __str__(self):
        return f"DataProduct(id={self.id})"

    def validate_policy(self, consumer: "DSConnector") -> bool:
        return DCAT3(self.metadata).validate_policy(consumer.auth_client.user_context)


class Catalog:
    def __init__(self, items: list[DataProduct]) -> None:
        self.items = items

    def __str__(self):
        return f"Catalog(items={[item.id for item in self.items]})"

    def get(self, id: str) -> DataProduct | None:
        for item in self.items:
            if item.id == id:
                return item
        return None

    def get_all(self) -> list[DataProduct]:
        return self.items


# --------------------------------------------------------------------------------------


class DSConnector:
    crypto_provider: CryptoProvider
    auth_client: AuthClient

    def __init__(self, crypto_provider: CryptoProvider, auth_client: AuthClient):
        self.crypto_provider = crypto_provider
        self.auth_client = auth_client

        private_key, public_key = self.crypto_provider.generate_keys()
        self.private_key = private_key
        self.public_key = public_key


class Consumer(DSConnector):
    def __str__(self):
        return f"Consumer(aid={self.auth_client.get_aid()})"

    def create_contract_request(self, dataproduct: DataProduct) -> ContractRequest:
        return ContractRequest(
            dataproduct=dataproduct,
            consumer=self,
            consumer_signature=self.crypto_provider.sign(
                dataproduct.metadata, self.private_key
            ),
        )

    def validate_provider_signature(self, contract: Contract) -> bool:
        return self.crypto_provider.verify(
            contract.dataproduct.metadata,
            contract.provider_signature,
            contract.provider.public_key,
        )


class Provider(DSConnector):
    def __init__(
        self,
        crypto_provider: CryptoProvider,
        auth_client: AuthClient,
        catalog: Catalog,
    ):
        self.catalog = catalog
        super().__init__(crypto_provider=crypto_provider, auth_client=auth_client)

    def __str__(self):
        return f"Provider(aid={self.auth_client.get_aid()}, catalog={self.catalog})"

    def validate_request_contract(self, request: ContractRequest) -> bool:
        """
        Validate the request contract by checking the policy and the signature.
        """
        local_dataproduct = self.catalog.get(request.dataproduct.id)
        if (
            local_dataproduct is None
            or local_dataproduct.metadata != request.dataproduct.metadata
        ):
            return False
        return request.dataproduct.validate_policy(
            request.consumer
        ) and self.crypto_provider.verify(
            request.dataproduct.metadata,
            request.consumer_signature,
            request.consumer.public_key,
        )

    def sign_request_contract(self, request: ContractRequest) -> Contract:
        return Contract(
            request=request,
            provider=self,
            provider_signature=self.crypto_provider.sign(
                request.dataproduct.metadata, self.private_key
            ),
        )

    def get_real_data(self, contract: Contract) -> Any:
        """
        Validate the provider's signature and get the real data from the contract.
        """
        if not self.crypto_provider.verify(
            contract.dataproduct.metadata,
            contract.provider_signature,
            contract.provider.public_key,
        ):
            raise Exception("Invalid signature")
        return DCAT3(contract.dataproduct.metadata).get_all_distribution_download_urls()


# --------------------------------------------------------------------------------------


class ClearingHouse:
    logs: list[str] = []

    def __str__(self):
        return "ClearingHouse()"

    def register_contract_request(self, contract_request: ContractRequest) -> None:
        self.logs.append(f"Contract request registered: {contract_request}")

    def register_contract(self, contract: Contract) -> None:
        self.logs.append(f"Contract registered: {contract}")

    def confirm_contract(self, contract: Contract) -> None:
        self.logs.append(f"Contract confirmed: {contract}")

    def register_data_use(self, contract: Contract) -> None:
        self.logs.append(f"Data used: {contract}")

    def confirm_data_use(self, contract: Contract, user: DSConnector) -> None:
        self.logs.append(f"Data use confirmed: {user}, {contract}")

    def formatted_logs(self) -> str:
        formatted_logs = "\n=== Clearing House Logs ===\n"
        for index, log in enumerate(self.logs, start=1):
            formatted_logs += f"{index}. {log}\n"
        formatted_logs += "===========================\n"
        return formatted_logs


# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------


def sign_contract_and_use_data():
    logger.debug('Starting use case "sign_contract_and_use_data"')

    # --- Setup ---
    logger.debug("\n=== Setup ===")

    crypto_provider = CryptoProvider()
    clearing_house = ClearingHouse()

    consumer = Consumer(
        crypto_provider=crypto_provider,
        auth_client=AuthClient(user_context=UserContext(country="NL")),
    )
    provider = Provider(
        crypto_provider=crypto_provider,
        auth_client=AuthClient(user_context=UserContext(country="US")),
        catalog=Catalog(
            items=[
                DataProduct(id="Dataproduct 1", metadata=DATAPRODUCT_METADATA),
            ]
        ),
    )

    logger.debug(f"\nConsumer: {consumer}")
    logger.debug(f"Provider: {provider}")
    logger.debug(f"Clearing house: {clearing_house}")

    logger.debug("\n=== Negotiation ===")

    # --- Consumer ---
    logger.debug("\n--- Consumer ---")

    # Get dataproduct
    dataproduct = provider.catalog.get_all()[0]
    logger.debug(f"Consumer selected data product: {dataproduct}")

    # Create contract request
    if not dataproduct.validate_policy(consumer):
        raise Exception("Policy is not valid")
    contract_request = consumer.create_contract_request(dataproduct)
    clearing_house.register_contract_request(contract_request)
    logger.debug(f"Consumer created contract request: {contract_request}")
    logger.debug("Consumer sent contract request to provider")

    # --- Provider ---
    logger.debug("\n--- Provider ---")

    # Sign contract
    if not provider.validate_request_contract(contract_request):
        raise Exception(
            "Request rejected: policy is not valid or signature is not valid"
        )
    contract = provider.sign_request_contract(contract_request)
    clearing_house.register_contract(contract)
    logger.debug(f"Provider validated and signed contract: {contract}")
    logger.debug("Provider sent contract to consumer")

    # --- Consumer ---
    logger.debug("\n--- Consumer ---")

    # Confirm receipt of contract
    if not consumer.validate_provider_signature(contract):
        raise Exception("Contract rejected: providers's signature is not valid")
    clearing_house.confirm_contract(contract)
    logger.debug("Consumer confirmed receipt of contract")

    # Use data
    try:
        # --- Consumer ---
        clearing_house.register_data_use(contract)
        data = provider.get_real_data(contract)
        clearing_house.confirm_data_use(contract, consumer)
        logger.info(f"Consumer used data: {data}")
    except Exception as e:
        logger.error(f"\nError: {e}")
    else:
        # --- Provider ---
        logger.debug("\n--- Provider ---")
        logger.debug(f"Provider confirmed data use: {data}")
        clearing_house.confirm_data_use(contract, provider)

    logger.info(clearing_house.formatted_logs())

    logger.debug('Use case "sign_contract_and_use_data" finished')


if __name__ == "__main__":
    sign_contract_and_use_data()
