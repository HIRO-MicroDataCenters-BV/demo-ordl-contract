DATAPRODUCT_METADATA = """
{
  "@context": {
    "dcat": "http://www.w3.org/ns/dcat#",
    "dcterms": "http://purl.org/dc/terms/",
    "odrl": "http://www.w3.org/ns/odrl/2/"
  },
    "@graph": [
        {
            "@id": "http://example.org/dataset/1",
            "@type": "dcat:Dataset",
            "dcterms:identifier": "http://example.org/dataset/1",
            "dcterms:title": "Dataset 1",
            "dcat:distribution": {
                "@id": "http://example.org/distribution/1"
            },
            "dct:rights": {
                "@id": "http://example.org/policy/1"
            }
        },
        {
            "@id": "http://example.org/distribution/1",
            "@type": "dcat:Distribution",
            "dcat:downloadURL": "http://example.org/dataset/1.csv"
        },
        {
            "@id": "http://example.org/distribution/2",
            "@type": "dcat:Distribution",
            "dcat:downloadURL": "http://example.org/dataset/2.csv"
        },
        {
            "@id": "http://example.org/policy/1",
            "@type": "odrl:Policy",
            "odrl:permission": [
                {
                    "odrl:target": {
                        "@id": "http://example.org/distribution/2"
                    },
                    "odrl:assignee": {
                        "@id": "odrl:All"
                    },
                    "odrl:action": {
                        "@id": "odrl:read"
                    },
                    "odrl:constraint": [
                        {
                        "odrl:leftOperand": {
                            "@id": "odrl:spatial"
                        },
                        "odrl:operator": {
                            "@id": "odrl:eq"
                        },
                        "odrl:rightOperand": "NL"
                        }
                    ]
                }
            ]
        }
    ]
}
"""

DEFAULT_SERVICE_POLICY = """
{
    "@context": {
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "schema": "http://schema.org/",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    },
    "@type": "odrl:Policy",
    "odrl:permission": []
}
"""
