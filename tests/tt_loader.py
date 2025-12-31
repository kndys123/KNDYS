import importlib.machinery
import importlib.util
import os
import sys


def load_tt():
    """Load the monolithic tt module regardless of extension."""
    if 'tt' in sys.modules:
        return sys.modules['tt']
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    module_path = os.path.join(root_dir, 'tt')
    loader = importlib.machinery.SourceFileLoader('tt', module_path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    sys.modules['tt'] = module
    return module
