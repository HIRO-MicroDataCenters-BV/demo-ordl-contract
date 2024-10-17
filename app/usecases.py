from typing import Any

import logging
import sys

from rdflib import RDF, BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCAT, ODRL2

from .crypto_provider import CryptoProvider
from .data import DATAPRODUCT_METADATA, DEFAULT_SERVICE_POLICY

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


SCHEMA = Namespace("http://schema.org/")


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

    def __init__(self, aid: str, user_context: UserContext):
        self.aid = aid
        self.user_context = user_context

    def __str__(self) -> str:
        return f"AuthClient(aid={self.aid})"

    def get_aid(self) -> str:
        return self.aid

    def get_context(self) -> UserContext:
        return self.user_context


# --------------------------------------------------------------------------------------


class SkipValidation(Exception):
    ...


class BaseValidator:
    def validate(
        self,
        person: AuthClient,
        constraint_triplet: tuple[Any, Any, Any],
    ) -> bool:
        raise NotImplementedError("Subclasses must implement this method")


class CountryValidator(BaseValidator):
    def validate(
        self,
        person: AuthClient,
        constraint_triplet: tuple[Any, Any, Any],
    ) -> bool:
        left_operand: URIRef = constraint_triplet[0]
        operator: URIRef = constraint_triplet[1]
        right_operand: Literal = constraint_triplet[2]

        if left_operand != ODRL2.spatial:
            raise SkipValidation()

        if operator != ODRL2.eq:
            raise Exception(f"Operator {operator} is not supported")

        return (
            left_operand == ODRL2.spatial
            and operator == ODRL2.eq
            and right_operand == Literal(person.user_context.country)
        )


class Policy:
    def __init__(self, metadata: str):
        self.graph = Graph()
        self.graph.parse(data=metadata, format="json-ld")
        self.validators = [CountryValidator()]

    def validate_policy(self, person: AuthClient, action: URIRef) -> list[str]:
        result = []

        for policy in self.graph.subjects(RDF.type, ODRL2.Policy):
            for permission in self.graph.objects(policy, ODRL2.permission):
                target = self.graph.value(permission, ODRL2.target)
                assignee = self.graph.value(permission, ODRL2.assignee)
                assignee_id = self.graph.value(
                    subject=assignee, predicate=SCHEMA.identifier
                )

                actions = []
                for action_ in self.graph.objects(permission, ODRL2.action):
                    actions.append(action_)

                if action not in actions:
                    continue

                if assignee != ODRL2.All and str(assignee_id) != person.get_aid():
                    continue

                are_constraints_passed = True
                for constraint in self.graph.objects(permission, ODRL2.constraint):
                    constraint_triplet = (
                        self.graph.value(constraint, ODRL2.leftOperand),
                        self.graph.value(constraint, ODRL2.operator),
                        self.graph.value(constraint, ODRL2.rightOperand),
                    )

                    for validator in self.validators:
                        try:
                            if not validator.validate(person, constraint_triplet):
                                are_constraints_passed = False
                        except SkipValidation:
                            continue

                if are_constraints_passed:
                    result.append(str(target))

        return result

    def add_permission(
        self,
        service_target: str,
        person_aid: str,
        action: URIRef,
    ) -> None:
        policy = next(self.graph.subjects(RDF.type, ODRL2.Policy), None)
        if policy is None:
            raise Exception("Policy not found")

        permission = BNode()

        assignee = next(
            (
                s
                for s in self.graph.subjects(RDF.type, SCHEMA.Person)
                if str(self.graph.value(s, SCHEMA.identifier)) == person_aid
            ),
            None,
        )
        if assignee is None:
            assignee = BNode()

        self.graph.add((policy, ODRL2.permission, permission))
        self.graph.add((permission, ODRL2.target, URIRef(service_target)))
        self.graph.add((permission, ODRL2.assignee, assignee))
        self.graph.add((assignee, RDF.type, SCHEMA.Person))
        self.graph.add((assignee, SCHEMA.identifier, Literal(person_aid)))
        self.graph.add((permission, ODRL2.action, URIRef(action)))

    def get_distribution_download_url(self, distribution: str) -> str | None:
        for distribution_ in self.graph.subjects(RDF.type, DCAT.Distribution):
            if distribution_ == URIRef(distribution):
                download_url = self.graph.value(
                    subject=distribution_, predicate=DCAT.downloadURL
                )
                return str(download_url)
        return None

    def to_json(self) -> str:
        context = {"@context": {"odrl": str(ODRL2), "schema": SCHEMA, "rdf": str(RDF)}}
        return self.graph.serialize(format="json-ld", context=context)


# --------------------------------------------------------------------------------------


class ContractRequest:
    def __init__(
        self,
        dataproduct: "DataProduct",
        distribution: str,
        consumer: "DSConnectorBase",
        consumer_signature: bytes,
    ):
        self.dataproduct = dataproduct
        self.distribution = distribution
        self.consumer = consumer
        self.consumer_signature = consumer_signature

    def __str__(self):
        return (
            f"ContractRequest("
            f"dataproduct={self.dataproduct}, "
            f"distribution={self.distribution}, "
            f"consumer_aid={self.consumer.auth_client.get_aid()}, "
            f"consumer_signature={cut_string(self.consumer_signature.hex())})"
        )


class Contract(ContractRequest):
    def __init__(
        self,
        request: ContractRequest,
        provider: "DSConnectorBase",
        provider_signature: bytes,
    ):
        super().__init__(
            dataproduct=request.dataproduct,
            distribution=request.distribution,
            consumer=request.consumer,
            consumer_signature=request.consumer_signature,
        )
        self.provider = provider
        self.provider_signature = provider_signature

    def __str__(self):
        return (
            f"Contract("
            f"dataproduct={self.dataproduct}, "
            f"distribution={self.distribution}, "
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

    def validate_policy(self, consumer: "DSConnectorBase") -> list[str]:
        return Policy(self.metadata).validate_policy(consumer.auth_client, ODRL2.read)


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


class DSConnectorBase:
    crypto_provider: CryptoProvider
    auth_client: AuthClient

    def __init__(self, crypto_provider: CryptoProvider, auth_client: AuthClient):
        self.crypto_provider = crypto_provider
        self.auth_client = auth_client

        private_key, public_key = self.crypto_provider.generate_keys()
        self.private_key = private_key
        self.public_key = public_key


class Consumer(DSConnectorBase):
    def __str__(self):
        return f"Consumer(aid={self.auth_client.get_aid()})"

    def create_contract_request(
        self, dataproduct: DataProduct, distribution: str
    ) -> ContractRequest:
        return ContractRequest(
            dataproduct=dataproduct,
            distribution=distribution,
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


class Provider(DSConnectorBase):
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

        distributions = request.dataproduct.validate_policy(request.consumer)
        if request.distribution not in distributions:
            return False

        return self.crypto_provider.verify(
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

    def return_real_data(self, contract: Contract) -> Any:
        """
        Validate the provider's signature and return the real data.
        """

        if not self.crypto_provider.verify(
            contract.dataproduct.metadata,
            contract.consumer_signature,
            contract.consumer.public_key,
        ):
            raise Exception("Invalid consumer's signature")

        if not self.crypto_provider.verify(
            contract.dataproduct.metadata,
            contract.provider_signature,
            contract.provider.public_key,
        ):
            raise Exception("Invalid provider's signature")

        return Policy(contract.dataproduct.metadata).get_distribution_download_url(
            contract.distribution
        )


# --------------------------------------------------------------------------------------


class Service:
    id: str
    policy: str = DEFAULT_SERVICE_POLICY

    def __init__(self, id: str):
        self.id = id

    def __str__(self):
        return f"Service(id={self.id})"

    def get_policy(self) -> str:
        return self.policy

    def add_permissions(self, person: AuthClient, actions: list[URIRef]) -> None:
        new_policy = Policy(self.policy)
        for action in actions:
            new_policy.add_permission(self.id, person.get_aid(), action)
        self.policy = new_policy.to_json()

    def has_permission(self, person: AuthClient, action: URIRef) -> bool:
        targets = Policy(self.policy).validate_policy(person, action)
        return self.id in targets


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

    def confirm_data_use(self, contract: Contract, user: DSConnectorBase) -> None:
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
    logger.info('Starting use case "sign_contract_and_use_data"')

    # --- Setup ---
    logger.info("\n=== Setup ===")

    crypto_provider = CryptoProvider()
    clearing_house = ClearingHouse()

    consumer = Consumer(
        crypto_provider=crypto_provider,
        auth_client=AuthClient(
            aid="http://example.org/person/1",
            user_context=UserContext(country="NL"),
        ),
    )
    provider = Provider(
        crypto_provider=crypto_provider,
        auth_client=AuthClient(
            aid="http://example.org/person/2",
            user_context=UserContext(country="US"),
        ),
        catalog=Catalog(
            items=[
                DataProduct(id="Dataproduct 1", metadata=DATAPRODUCT_METADATA),
            ]
        ),
    )

    logger.info(f"\nConsumer: {consumer}")
    logger.info(f"Provider: {provider}")
    logger.info(f"Clearing house: {clearing_house}")

    logger.info("\n=== Negotiation ===")

    # --- Consumer ---
    logger.info("\n--- Consumer ---")

    # Consumer selects dataproduct
    dataproduct = provider.catalog.get_all()[0]
    logger.info(f"Consumer selected data product: {dataproduct}")

    # Consumer creates contract request
    distributions = dataproduct.validate_policy(consumer)
    if len(distributions) == 0:
        raise Exception("Policy is not valid")
    contract_request = consumer.create_contract_request(dataproduct, distributions[0])
    clearing_house.register_contract_request(contract_request)
    logger.info(f"Consumer created contract request: {contract_request}")
    logger.info("Consumer sent contract request to provider")

    # --- Provider ---
    logger.info("\n--- Provider ---")

    # Provider validates and signs contract
    if not provider.validate_request_contract(contract_request):
        raise Exception(
            "Request rejected: policy is not valid or signature is not valid"
        )
    contract = provider.sign_request_contract(contract_request)
    clearing_house.register_contract(contract)
    logger.info(f"Provider validated and signed contract: {contract}")
    logger.info("Provider sent contract to consumer")

    # --- Consumer ---
    logger.info("\n--- Consumer ---")

    # Consumer validates providers's signature
    if not consumer.validate_provider_signature(contract):
        raise Exception("Contract rejected: providers's signature is not valid")
    clearing_house.confirm_contract(contract)
    logger.info("Consumer confirmed receipt of contract")

    try:
        # --- Consumer ---
        # Consumer uses data
        clearing_house.register_data_use(contract)
        data = provider.return_real_data(contract)
        clearing_house.confirm_data_use(contract, consumer)
        assert data == "http://example.org/dataset/2.csv"
        logger.info(f"Consumer used data: {data}")
    except Exception as e:
        logger.error(f"\nError: {e}")
    else:
        # --- Provider ---
        # Provider confirms data use
        logger.info("\n--- Provider ---")
        logger.info(f"Provider confirmed data use: {data}")
        clearing_house.confirm_data_use(contract, provider)

    logger.info(clearing_house.formatted_logs())

    logger.info('Use case "sign_contract_and_use_data" finished')


def delegate_permission_and_service_access():
    logger.info('Starting use case "delegate_permission_and_service_access"')

    # --- Setup ---
    logger.info("\n=== Setup ===")

    owner = AuthClient(
        aid="http://example.org/person/1", user_context=UserContext(country="NL")
    )
    person = AuthClient(
        aid="http://example.org/person/2", user_context=UserContext(country="NL")
    )
    person2 = AuthClient(
        aid="http://example.org/person/3", user_context=UserContext(country="NL")
    )

    service = Service(id="http://example.org/service")
    service.add_permissions(owner, [ODRL2.use, ODRL2.grantUse])

    logger.info(f"\nService: {service}")
    logger.info(f"Service policy: {service.get_policy()}")

    # --- Delegate permission ---
    logger.info("\n=== Delegate permission ===")

    if service.has_permission(owner, ODRL2.grantUse):
        service.add_permissions(person, [ODRL2.write])

    logger.info(f"\nNew service policy: {service.get_policy()}")

    # --- Current permissions ---
    logger.info("\n=== Current permissions ===")

    logger.info("\nOwner has permissions to use and grantUse")
    logger.info("Person has permission to write")
    logger.info("Person2 does not have permissions")

    # --- Check permissions ---
    logger.info("\n=== Check permissions ===")

    has_owner_use = service.has_permission(owner, ODRL2.use)
    logger.info(f'\nDoes owner have permission "use": {has_owner_use}')
    assert has_owner_use

    has_owner_grant_use = service.has_permission(owner, ODRL2.grantUse)
    logger.info(f'Does owner have permission "grantUse": {has_owner_grant_use}')
    assert has_owner_grant_use

    has_person_read = service.has_permission(person, ODRL2.read)
    logger.info(f"Does person have permission to read: {has_person_read}")
    assert not has_person_read

    has_person_write = service.has_permission(person, ODRL2.write)
    logger.info(f"Does person have permission to write: {has_person_write}")
    assert has_person_write

    has_person2_read = service.has_permission(person2, ODRL2.read)
    logger.info(f"Does person2 have permission to read: {has_person2_read}")
    assert not has_person2_read

    logger.info('\nUse case "delegate_permission_and_service_access" finished')


# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python usecases.py <usecase>")
        print("Available usecases:")
        print("1. sign_contract_and_use_data")
        print("2. delegate_permission_and_service_access")
        sys.exit(1)

    usecase = sys.argv[1]

    if usecase == "1":
        sign_contract_and_use_data()
    elif usecase == "2":
        delegate_permission_and_service_access()
    else:
        print(f"Unknown usecase: {usecase}")
        sys.exit(1)
