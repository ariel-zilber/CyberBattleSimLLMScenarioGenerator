# cli.py
import argparse
import os
from enum import IntEnum

import yaml

from pipeline.cbsim.generator import UniversalNetworkGenerator


def _int_enum_representer(dumper, val):
    return dumper.represent_int(int(val))


# Register for all IntEnum subclasses so yaml.safe_load can read node files back
yaml.add_multi_representer(IntEnum, _int_enum_representer)


def _save_yaml(data, path: str) -> None:
    with open(path, 'w') as f:
        yaml.dump(data, f, sort_keys=False)


def generate_scenario(config_path: str, out_dir: str, seed: int = None) -> None:
    """Generate one scenario in-process and write nodes/identifiers/vuln_library to out_dir."""
    for subdir in ['nodes', 'identifiers', 'vulnerability_library']:
        os.makedirs(os.path.join(out_dir, subdir), exist_ok=True)

    gen = UniversalNetworkGenerator(domain_config_path=config_path, seed=seed)
    result = gen.generate()

    for node_id, node_info in result['nodes'].items():
        _save_yaml(node_info.to_dict(), os.path.join(out_dir, 'nodes', f'{node_id}.yaml'))

    _save_yaml(result['identifiers'].to_dict(),
               os.path.join(out_dir, 'identifiers', 'identifiers.yaml'))
    _save_yaml(result['vulnerability_library'],
               os.path.join(out_dir, 'vulnerability_library', 'vulnerability_library.yaml'))


def get_arg_parse():
    parser = argparse.ArgumentParser(description='Generate a CyberBattleSim scenario from a domain config YAML')
    parser.add_argument('domain_config_path', type=str, help='Path to domains.yaml')
    parser.add_argument('out_dir', type=str, help='Output directory')
    parser.add_argument('--seed', type=int, default=None, help='Random seed for reproducibility')
    return parser


if __name__ == '__main__':
    args = get_arg_parse().parse_args()
    generate_scenario(args.domain_config_path, args.out_dir, seed=args.seed)
