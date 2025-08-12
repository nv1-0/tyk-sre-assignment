import socketserver
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from kubernetes import client, config
from kubernetes.client.rest import ApiException


# Try loading kubeconfig (in-cluster or local)
try:
    config.load_incluster_config()
except config.config_exception.ConfigException:
    config.load_kube_config()

apps_v1 = client.AppsV1Api()
core_v1 = client.CoreV1Api()
networking_v1 = client.NetworkingV1Api()


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/healthz":
            self.healthz()
        elif path == "/version":
            try:
                version = get_kubernetes_version()
                self.respond(200, version)
            except Exception as e:
                self.respond(500, str(e))
        elif path == "/deployments/health":
            try:
                query = parse_qs(parsed_path.query)
                namespace = query.get("namespace", [None])[0]
                result = check_deployment_health(namespace)
                self.respond(200, str(result))
            except Exception as e:
                self.respond(500, str(e))
        elif path == "/api/health":
            try:
                check_api_health()
                self.respond(200, "API server reachable")
            except Exception as e:
                self.respond(500, str(e))
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)

        if path == "/network/block":
            try:
                namespace1 = query.get("namespace1", [None])[0]
                selector1 = query.get("selector1", [None])[0]
                namespace2 = query.get("namespace2", [None])[0]
                selector2 = query.get("selector2", [None])[0]

                if None in (namespace1, selector1, namespace2, selector2):
                    self.respond(400, "Missing required parameters")
                    return

                result = block_communication(namespace1, selector1, namespace2, selector2)
                self.respond(200, str(result))
            except Exception as e:
                self.respond(500, str(e))
        else:
            self.send_error(404)

    def healthz(self):
        """Simple health check"""
        self.respond(200, "ok")

    def respond(self, status: int, content: str):
        """Write response"""
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes(content, "UTF-8"))


def get_kubernetes_version(api_client=None) -> str:
    if api_client is None:
        api_client = client.VersionApi()
    else:
        api_client = client.VersionApi(api_client)
    version = api_client.get_code()
    return version.git_version


def check_deployment_health(namespace: str = None):
    deployments = (
        apps_v1.list_namespaced_deployment(namespace=namespace).items
        if namespace else
        apps_v1.list_deployment_for_all_namespaces().items
    )

    results = []
    for dep in deployments:
        desired = dep.spec.replicas
        available = dep.status.available_replicas or 0
        results.append({
            "namespace": dep.metadata.namespace,
            "name": dep.metadata.name,
            "desired": desired,
            "available": available,
            "healthy": desired == available
        })

    return {"all_healthy": all(r["healthy"] for r in results), "deployments": results}


def block_communication(ns1: str, selector1: str, ns2: str, selector2: str):
    label_dict_1 = {kv.split("=")[0]: kv.split("=")[1] for kv in selector1.split(",")}
    label_dict_2 = {kv.split("=")[0]: kv.split("=")[1] for kv in selector2.split(",")}

    # Policy for ns1 pods: block ingress from ns2 pods with selector2 only
    policy1 = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=f"deny-from-{ns2}-to-{ns1}"),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels=label_dict_1),
            policy_types=["Ingress"],
            ingress=[
                # Allow all traffic except from ns2 with specific selector
                client.V1NetworkPolicyIngressRule(),  # Allow all by default
                # Explicitly deny from ns2 with selector2 (this is handled by omitting it)
            ]
        )
    )

    # Create a deny-all policy first, then allow everything except the target
    policy1 = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=f"deny-from-{ns2}-to-{ns1}"),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels=label_dict_1),
            policy_types=["Ingress"],
            ingress=[
                # Allow from same namespace
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            pod_selector=client.V1LabelSelector()
                        )
                    ]
                ),
                # Allow from all other namespaces except ns2
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_expressions=[
                                    client.V1LabelSelectorRequirement(
                                        key="kubernetes.io/metadata.name",
                                        operator="NotIn",
                                        values=[ns2]
                                    )
                                ]
                            )
                        )
                    ]
                ),
                # Allow from ns2 but not with selector2
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": ns2}
                            ),
                            pod_selector=client.V1LabelSelector(
                                match_expressions=[
                                    client.V1LabelSelectorRequirement(
                                        key=list(label_dict_2.keys())[0],
                                        operator="NotIn",
                                        values=[list(label_dict_2.values())[0]]
                                    )
                                ]
                            )
                        )
                    ]
                )
            ]
        )
    )

    networking_v1.create_namespaced_network_policy(namespace=ns1, body=policy1)

    # Policy for ns2 pods: block ingress from ns1 pods with selector1 only
    policy2 = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=f"deny-from-{ns1}-to-{ns2}"),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels=label_dict_2),
            policy_types=["Ingress"],
            ingress=[
                # Allow from same namespace
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            pod_selector=client.V1LabelSelector()
                        )
                    ]
                ),
                # Allow from all other namespaces except ns1
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_expressions=[
                                    client.V1LabelSelectorRequirement(
                                        key="kubernetes.io/metadata.name",
                                        operator="NotIn",
                                        values=[ns1]
                                    )
                                ]
                            )
                        )
                    ]
                ),
                # Allow from ns1 but not with selector1
                client.V1NetworkPolicyIngressRule(
                    _from=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": ns1}
                            ),
                            pod_selector=client.V1LabelSelector(
                                match_expressions=[
                                    client.V1LabelSelectorRequirement(
                                        key=list(label_dict_1.keys())[0],
                                        operator="NotIn",
                                        values=[list(label_dict_1.values())[0]]
                                    )
                                ]
                            )
                        )
                    ]
                )
            ]
        )
    )

    networking_v1.create_namespaced_network_policy(namespace=ns2, body=policy2)

    return {"status": "communication_blocked_between_namespaces", "ns1": ns1, "ns2": ns2}




def check_api_health():
    core_v1.get_api_resources()


def start_server(address):
    try:
        host, port = address.split(":")
    except ValueError:
        print("Invalid address format, expected host:port")
        return

    with socketserver.TCPServer((host, int(port)), AppHandler) as httpd:
        print(f"Server listening on {address}")
        httpd.serve_forever()


if __name__ == "__main__":
    start_server("0.0.0.0:8080")
