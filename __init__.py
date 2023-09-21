from pathlib import Path

from capa.features.extractors.binja.extractor import BinjaFeatureExtractor
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle
from capa.rules import Rule, RuleSet, Scope
from capa.features.common import Result
from capa.features.address import _NoAddress as NoAddress
import capa.main as capa

import binaryninja as binja


RULE_PATH = Path("~/.binaryninja/plugin_data/rules/capa")
DEFAULT_TAG = "CAPA"
DEFAULT_ICON = "🤔"
PROGRESS_TEXT = "Extracting features using CAPA"


# Ideas:
# - Some rules marks basic blocks explicitly -- add a mapping for rule to basic block highlight color?
ignore_rule_matches = [
    "encrypt data using RC4 PRGA",
    "resolve function by parsing PE exports",
    "inspect section memory permissions",
    "hash data with CRC32",
    "allocate memory",
    "allocate RW memory",
]


tags = {
    DEFAULT_TAG: DEFAULT_ICON,
    "Anti-Analysis": "🛡️",
    "Anti-VM": "📀",
    "Binary Introspection": "🔍",
    "C2 Communication": "🦹",
    "Camera": "📷",
    "Low Level Features": "⚙️",
    "Memory": "📐",
    "Firewall": "🧱",
    "Clipboard": "📋",
    "Control Flow": "↩️",
    "Crypto": "🔐",
    "Data Manipulation": "🚜",
    "Debugging": "🧰",
    "Driver Interaction": "🔧",
    "Runtime Execution": "🍴",
    "File System": "🗂️",
    "Host Information": "🖥️",
    "Impact": "💣",  # Destructive impact?
    "Inter-Process Communication": "🪈",
    "Keyboard": "⌨️",
    "Malware": "☣️",
    "Microphone": "🎤",
    "Network Traffic": "🕸️",
    "Nursery": "👶",
    "Obfuscation": "🛡️",
    "Packing": "🛡️",
    "Persistence": "📲",
    "Process Control": "🍴",
    "Registry": "🧊",
    "Targeting": "🎯",
    "Graphical UI": "🪟",  # "🗔",
    "Thread Local Storage": "🧵",
    "User Information": "🪪",
    "User Observation": "📸",  # A bit too generic?
    "Synchronization": DEFAULT_ICON,
}


rule_map = {
    # High level rules
    "create or open file": "File System",
    "create or open registry key": "Registry",
    "delay execution": "Control Flow",
    "contain loop": "Control Flow",
    # TLS
    "executable/pe/section/tls": "Thread Local Storage",
    "host-interaction/process/get thread local storage value": "Thread Local Storage",
    "host-interaction/process/set thread local storage value": "Thread Local Storage",
    "host-interaction/process/allocate thread local storage": "Thread Local Storage",
    # Debugging
    "executable/pe/pdb": "Debugging",
    "host-interaction/log/debug": "Debugging",
    # Introspection
    "load-code/pe/parse PE header": "Binary Introspection",
    "load-code/pe/inspect section memory permissions": "Binary Introspection",
    # Other random
    "nursery/get network parameters": "Host Information",
    "lib/get OS version": "Host Information",
    "collection/get geographical location": "Host Information",
    "host-interaction/cli/accept command line arguments": "Process Control",
    "host-interaction/process/terminate": "Process Control",
    "nursery/terminate process": "Process Control",
    "host-interaction/environment-variable": "Host Information",
    "host-interaction/driver": "Driver Interaction",
    "host-interaction/hardware/keyboard": "Keyboard",
    "host-interaction/hardware/mouse": "Mouse",
    "host-interaction/hardware/cdrom": "CD drive",
    "host-interaction/hardware": "Host Information",
    "host-interaction/mutex": "Synchronization",
    "load-code/pe/resolve function by parsing PE exports": "Library",
    # Categories
    "anti-analysis/anti-vm": "Anti-VM",
    "anti-analysis/obfuscation": "Obfuscation",
    "anti-analysis": "Anti-Analysis",
    "host-interaction/process/create": "Process Control",
    "host-interaction/file-system": "File System",
    "host-interaction/clipboard": "Clipboard",
    "host-interaction/os": "Host Information",
    "host-interaction/network/address": "Host Information",
    "host-interaction/registry": "Registry",
    "host-interaction/gui": "Graphical UI",
    "host-interaction/firewall": "Firewall",
    "communication/dns": "Network Traffic",
    "communication/http": "Network Traffic",
    "communication/ftp": "Network Traffic",
    "communication/c2": "C2 Communication",
    "communication/icmp": "Network Traffic",
    "communication/ip": "Network Traffic",
    "communication/socket": "Network Traffic",
    "communication/tcp": "Network Traffic",
    "communication/receive data": "Network Traffic",
    "communication/send data": "Network Traffic",
    "communication/mailslot": "Inter-Process Communication",
    "communication/named-pipe": "Inter-Process Communication",
    # This one's kinda up for debate.
    # Credentials should possibly be its own category.
    "collection/browser": "User Information",
    "collection/credit-card": "User Information",
    "collection/database/sql": "Database",
    "collection/database/wmi": "Host Information",
    "collection/file-managers": "User Information",
    "collection/keylog": "Keyboard",
    "collection/password-manager": "User Information",
    "collection/microphone": "Microphone",
    "collection/screenshot": "User Observation",
    "collection/webcam": "Camera",
    "collection/network": "Host Information",
    "data-manipulation/encryption": "Crypto",
    "data-manipulation/hmac": "Crypto",
    "impact": "Impact",
    # Don't know about these man
    "collection/group-policy": DEFAULT_TAG,
    # TODO
    "compiler": DEFAULT_TAG,
    "anti-analysis": "Anti-Analysis",
    "data-manipulation": "Data Manipulation",
    "executable": "Binary Introspection",
    "host-interaction": DEFAULT_TAG,
    "lib": "Low Level Features",
    "linking": "Library",
    "nursery/linked": "Library",
    "load-code": "Runtime Execution",
    "malware-family": "Malware",
    "persistence": "Persistence",
    "targeting": "Targeting",
}


class ProgressTrackingBinjaFeatureExtractor(BinjaFeatureExtractor):

    def __init__(self, *args, thread=None, **kwargs):
        if not thread:
            raise ValueError("Must provide a thread argument")

        super().__init__(*args, **kwargs)
        self.__thread = thread

    def extract_function_features(self, fh: FunctionHandle):
        self.__thread.progress = f"{PROGRESS_TEXT}: function at {hex(fh.inner.start)}"
        return super().extract_function_features(fh)

    def extract_file_features(self):
        self.__thread.progress = f"{PROGRESS_TEXT}: file features"
        return super().extract_file_features()

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle):
        self.__thread.progress = f"{PROGRESS_TEXT}: function at {hex(fh.inner.start)} ({repr(bbh.inner[1])})"
        return super().extract_basic_block_features(fh, bbh)


def tag_for_rule_meta(rule: Rule):
    namespace = rule.meta.get("namespace", "")
    path = "/".join([namespace, rule.name])

    if namespace in rule_map:
        return rule_map[namespace]

    elif rule.name in rule_map:
        return rule_map[rule.name]

    elif path in rule_map:
        return rule_map[path]

    else:
        for prefix, tag in rule_map.items():
            if path.startswith(prefix):
                return tag

    return DEFAULT_TAG


def get_feature_locations(result: Result):
    for loc in result.locations:
        yield (result, loc)

    for child in result.children:
        for item in get_feature_locations(child):
            yield item


def get_features(bv: binja.BinaryView, thread):

    rules_path = RULE_PATH.expanduser().glob("*/")
    rules = capa.get_rules(rules_path)

    extractor = ProgressTrackingBinjaFeatureExtractor(bv, thread=thread) 
    (matches, _) = capa.find_capabilities(rules, extractor)

    known_tags = set()
    thread.progress = f"{PROGRESS_TEXT}: Applying tags"

    for rule, resultset in matches.items():
        rule_meta = rules[rule]
        binja.log_info(f"Rule: {rule_meta.meta.get('namespace', '_')}/{rule_meta.name}")

        if "/" in rule and not rule_meta.scope is Scope.FILE:
            continue

        if "contain loop" in rule:
            continue

        # Figure out what tag to use
        tag_name = tag_for_rule_meta(rule_meta)
        if tag_name not in known_tags:
            known_tags.add(tag_name)
            # Verify that the tag actually exists, creating it if not
            if not bv.get_tag_type(tag_name):
                bv.create_tag_type(tag_name, tags.get(tag_name, DEFAULT_ICON))

        functions = set()
        for (addr, results) in resultset:
            #binja.log_info(f"result {type(addr)} {addr!r}")
            # Add function-level tags for all rules
            if addr != NoAddress:
                #binja.log_info(f"floc {addr!r} {hex(int(addr))} {type(addr)}")
                funcs = bv.get_functions_containing(addr)
                for func in funcs:
                    func.add_tag(tag_name, rule)

            # Skip tagging features for certain rules
            if rule in ignore_rule_matches:
                continue

            # Extract feature match locations
            for feature, loc in get_feature_locations(results):
                # For file-scoped rules, add tags directly to the BinaryView
                if rule_meta.scope == Scope.FILE:
                    bv.add_tag(loc, tag_name, rule + "\n\n ⇢ " + repr(feature.statement))
                # For non-file-scoped rules, add tags to the functions themselves
                elif loc != NoAddress:
                    funcs = bv.get_functions_containing(loc)
                    for func in funcs:
                        func.add_tag(tag_name, rule + "\n\n ⇢ " + repr(feature.statement), loc)


def prep_handlers(bv):

    def trigger_capa():

        class CapaThread(binja.BackgroundTaskThread):
            def run(self):
                get_features(bv, self)

        capajob = CapaThread(f"{PROGRESS_TEXT}...", can_cancel=False)
        capajob.start()

    binja.AnalysisCompletionEvent(bv, trigger_capa)

binja.BinaryViewType.add_binaryview_finalized_event(prep_handlers)


