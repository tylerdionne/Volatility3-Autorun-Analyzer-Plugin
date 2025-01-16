from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, info
from volatility3.plugins.windows.registry import hivelist, printkey
import traceback
import logging

# define autorun keys
autorun_keys = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
]

class AutorunAnalyzer(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'printkey', plugin = printkey.PrintKey, version = (1, 0, 0)),
        ]

    def analyze(self):
        reg_keys = []
        results = []

        # collect registry hives
        try:
            for reg_key in hivelist.HiveList.list_hives(
                context=self.context,
                base_config_path=self.config_path,
                layer_name=self.config['primary'],
                symbol_table=self.config['nt_symbols']
            ):
                reg_keys.append(reg_key)
        except Exception as e:
            logging.error(f"Error while listing registry hives: {e}")
            return []

        # scan autorun keys
        for hive in reg_keys:
            hive_name = hive.get_name()
            for run_key in autorun_keys:
                try:
                    hive_key = hive.get_key(run_key)
                    if hive_key:
                        for value in hive_key.get_values():
                            key_path = hive_key.get_key_path()
                            val_name = value.get_name()
                            try:
                                data_str = str(value.decode_data(), "utf-16").replace('\x00', '')
                            except Exception:
                                data_str = "Unable to decode"
                            results.append((data_str, hive_name, key_path, val_name))
                except Exception as e:
                    logging.warning(f"Error accessing key {run_key} in hive {hive_name}: {e}")

        return results

    def run(self):
        self.results = self.analyze()

        return renderers.TreeGrid(
            [
                ("Data String", str),
                ("Hive Name", str),
                ("Key Path", str),
                ("Value Name", str),
                ("Suspicious Label", str),
            ],
            self._generator(self.results)
        )

    def _generator(self, results):
        malicious_keywords = ["malware", "virus", "trojan", "malicious", "backdoor", "cryptominer", "botnet", "worm", "dropper", "payload", "phishing", "shellcode", "injector", "exploitkit", "meterpreter", "powersploit", "nc.exe", "mimikatz", "cobaltstrike", "reverse_shell", "rat", "cmd.exe", "powershell.exe", "hacktool", "persistence", "autorun", "startup", "load.exe", "hidden", "obfuscated", "suspicious", "stealer", "binder", "installer", "script", "temp", "runme", "drop", "update.exe"]
        for data_str, hive_name, key_path, val_name in results:
            is_suspicious = any(keyword.lower() in data_str.lower() for keyword in malicious_keywords)
            suspicious_label = "SUSPICIOUS" if is_suspicious else ""
            yield (0, [str(data_str), str(hive_name), str(key_path), str(val_name), suspicious_label])
