import json
import os
import networkx as nx
from email.utils import parseaddr


class CommunicationGraph:
    """
    Models a directed graph of historical corporate communication edges.
    Novel connections from unknown senders to high-value targets
    are assigned a structural risk score.
    """

    # High-value internal targets that warrant elevated scrutiny for novel senders
    HIGH_VALUE_TARGETS = {
        "accounts.payable@yourcompany.com",
        "finance@yourcompany.com",
        "ceo@yourcompany.com",
        "cfo@yourcompany.com",
        "payroll@yourcompany.com",
        "treasury@yourcompany.com",
    }

    STORAGE_FILE = 'graph_baseline.json'

    def __init__(self):
        self.graph = nx.DiGraph()
        self.load_graph()

    def load_graph(self):
        if os.path.exists(self.STORAGE_FILE):
            with open(self.STORAGE_FILE, 'r') as f:
                data = json.load(f)
            self.graph = nx.readwrite.json_graph.node_link_graph(data)
        else:
            self.seed_baseline()
            self.save_graph()

    def save_graph(self):
        data = nx.readwrite.json_graph.node_link_data(self.graph)
        with open(self.STORAGE_FILE, 'w') as f:
            json.dump(data, f)

    def seed_baseline(self):
        """
        Populates the graph with mock historical communication edges that
        represent normal, expected corporate mail flows. Each edge models a
        (sender, recipient) pair that has been seen previously.
        """
        baseline_edges = [
            # Known vendors → Accounts Payable
            ("billing@aws.amazon.com",              "accounts.payable@yourcompany.com"),
            ("invoices@office365vendor.com",        "accounts.payable@yourcompany.com"),
            ("noreply@github.com",                  "accounts.payable@yourcompany.com"),
            ("billing@atlassian.com",               "accounts.payable@yourcompany.com"),
            ("billing@salesforce.com",              "accounts.payable@yourcompany.com"),
            # HR / internal
            ("hr@yourcompany.com",                  "payroll@yourcompany.com"),
            ("hr@yourcompany.com",                  "ceo@yourcompany.com"),
            ("it@yourcompany.com",                  "ceo@yourcompany.com"),
            # Finance ↔ Accounting
            ("finance@yourcompany.com",             "accounts.payable@yourcompany.com"),
            ("accounts.payable@yourcompany.com",    "finance@yourcompany.com"),
            # Known external partners
            ("partner@trustedpartner.com",          "finance@yourcompany.com"),
            ("support@trustedpartner.com",          "it@yourcompany.com"),
            # Marketing / newsletters
            ("newsletter@mailchimp.com",            "marketing@yourcompany.com"),
            ("noreply@linkedin.com",                "hr@yourcompany.com"),
        ]

        for src, dst in baseline_edges:
            self.graph.add_edge(src.lower(), dst.lower())

    def _normalise(self, addr: str) -> str:
        """Strip display names and normalise to lowercase."""
        _, email = parseaddr(addr)
        return email.lower().strip() if email else addr.lower().strip()

    def evaluate_connection(self, sender: str, recipient: str) -> float:
        """
        Returns a structural risk score (0–40) for the given sender→recipient pair.

        Returns:
            0.0  – edge exists in baseline (known, trusted communication channel)
            40.0 – entirely novel connection to a high-value internal target
            10.0 – novel connection to a non-high-value recipient
        """
        src = self._normalise(sender)
        dst = self._normalise(recipient)

        if self.graph.has_edge(src, dst):
            return 0.0

        # Novel connection — assess recipient sensitivity
        if dst in self.HIGH_VALUE_TARGETS:
            return 40.0

        return 10.0

    def add_safe_connection(self, sender: str, recipient: str):
        """Add a learned safe edge to the graph and persist it."""
        src = self._normalise(sender)
        dst = self._normalise(recipient)
        if not self.graph.has_edge(src, dst):
            self.graph.add_edge(src, dst)
            self.save_graph()
