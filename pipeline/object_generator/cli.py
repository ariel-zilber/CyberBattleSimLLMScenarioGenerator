from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

from .claude_provider import ClaudeProviderError, call_claude_cli
from .compiler import write_compiled_scenario
from .dsl_parser import parse_dsl
from .expansion import ExpansionError, expand_scenario, parse_expansion_dsl
from .lark_generator import generate_expansion_with_model, generate_lark_with_model
from .lark_parser import parse_lark_dsl
from .path_analysis import analyze_paths
from .reporter import write_reports
from .runtime_verifier import RuntimeVerificationError, verify_runtime_solution
from .state_bfs import find_minimum_solution
from .validator import validate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and compile compact Scenario DSL")
    parser.add_argument("dsl", type=Path, nargs="?", help="Scenario DSL file")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--request", help="Generate Lark DSL from this request using Claude")
    parser.add_argument("--base", type=Path, help="Validated base Lark scenario to preserve")
    parser.add_argument("--expansion", type=Path, help="Typed Lark expansion to apply to --base")
    parser.add_argument("--claude-model", default="sonnet")
    parser.add_argument("--claude-timeout", type=int, default=120)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--verify-runtime", action="store_true")
    parser.add_argument("--cyberbattle-root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expansion_mode = bool(args.base)
    if args.expansion and not args.base:
        raise SystemExit("--expansion requires --base")
    if args.base and bool(args.expansion) == bool(args.request):
        raise SystemExit("With --base, provide exactly one --expansion file or --request")
    if args.dsl and (args.request or expansion_mode):
        raise SystemExit("A DSL file cannot be combined with generation or expansion options")
    if not args.dsl and not args.request and not expansion_mode:
        raise SystemExit("Provide a DSL file, --request, or --base with expansion input")
    if args.max_attempts < 1:
        raise SystemExit("--max-attempts must be at least 1")
    if args.claude_timeout < 1:
        raise SystemExit("--claude-timeout must be at least 1")

    expansion_result = None
    if expansion_mode:
        try:
            base_source = args.base.read_text(encoding="utf-8")
            base = parse_lark_dsl(base_source)
            if args.expansion:
                delta = parse_expansion_dsl(args.expansion.read_text(encoding="utf-8"))
                expansion_result = expand_scenario(base, delta)
                generated_expansion_source = None
            else:
                generated_expansion = generate_expansion_with_model(
                    base,
                    base_source,
                    args.request,
                    lambda prompt: call_claude_cli(
                        prompt, model=args.claude_model, timeout=args.claude_timeout
                    ),
                    max_attempts=args.max_attempts,
                )
                expansion_result = generated_expansion.expansion
                generated_expansion_source = generated_expansion.source
        except (ClaudeProviderError, ExpansionError, ValueError) as exc:
            print(json.dumps({"valid": False, "expansion_error": str(exc)}, indent=2))
            return 5
        spec = expansion_result.spec
    elif args.request:
        try:
            generated = generate_lark_with_model(
                args.request,
                lambda prompt: call_claude_cli(
                    prompt, model=args.claude_model, timeout=args.claude_timeout
                ),
                max_attempts=args.max_attempts,
            )
        except (ClaudeProviderError, ValueError) as exc:
            print(json.dumps({"valid": False, "generation_error": str(exc)}, indent=2))
            return 3
        spec = generated.spec
    else:
        source = args.dsl.read_text(encoding="utf-8")
        spec = parse_lark_dsl(source) if args.dsl.suffix == ".larkdsl" else parse_dsl(source)
    validation = validate(spec)
    bfs = find_minimum_solution(spec) if validation.valid else None
    path_analysis = analyze_paths(spec) if validation.valid and bfs and bfs.solved else None
    summary = {
        "valid": validation.valid,
        "errors": list(validation.errors),
        "warnings": list(validation.warnings),
        "solved": bool(bfs and bfs.solved),
        "minimum_depth": bfs.minimum_depth if bfs else None,
        "required_minimum_depth": spec.goal.minimum_depth,
        "required_zones_present": path_analysis.required_zones_present if path_analysis else False,
        "bypassable_mandatory": list(path_analysis.bypassable_mandatory) if path_analysis else [],
    }
    print(json.dumps(summary, indent=2))
    if not validation.valid or not bfs or not bfs.solved:
        return 1
    if bfs.minimum_depth is None or bfs.minimum_depth < spec.goal.minimum_depth:
        print("Shortcut detected; refusing to compile")
        return 2
    if path_analysis and not path_analysis.required_zones_present:
        print("Required zone sequence is absent from the minimum path; refusing to compile")
        return 2
    if spec.goal.maximum_depth is not None and bfs.minimum_depth > spec.goal.maximum_depth:
        print("Minimum solution exceeds configured maximum; refusing to compile")
        return 2
    if args.validate_only:
        return 0
    scenario_dir = write_compiled_scenario(spec, args.output)
    write_reports(spec, scenario_dir, validation, bfs)
    if expansion_result is not None:
        (scenario_dir / "expansion_validation.json").write_text(
            json.dumps({
                "base_fingerprint": expansion_result.base_fingerprint,
                "base_preserved": True,
                "added_nodes": list(expansion_result.added_nodes),
                "added_transitions": expansion_result.added_transitions,
                "added_firewall_policies": expansion_result.added_firewall_policies,
            }, indent=2) + "\n",
            encoding="utf-8",
        )
        if generated_expansion_source is not None:
            (scenario_dir / "generated.expansion.larkdsl").write_text(
                generated_expansion_source.rstrip() + "\n", encoding="utf-8"
            )
    if args.verify_runtime:
        try:
            runtime = verify_runtime_solution(
                spec, scenario_dir, bfs, cyberbattle_root=args.cyberbattle_root
            )
        except RuntimeVerificationError as exc:
            (scenario_dir / "runtime_validation.json").write_text(
                json.dumps({"runtime_verified": False, "runtime_error": str(exc)}, indent=2) + "\n",
                encoding="utf-8",
            )
            print(json.dumps({"runtime_verified": False, "runtime_error": str(exc)}, indent=2))
            return 4
        (scenario_dir / "runtime_validation.json").write_text(
            json.dumps(dataclasses.asdict(runtime), indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({
            "runtime_verified": runtime.passed,
            "symbolic_depth": runtime.symbolic_depth,
            "runtime_depth": runtime.runtime_depth,
            "bootstrap_actions": runtime.bootstrap_actions,
            "target_privilege": runtime.target_privilege,
        }, indent=2))
    print(f"Compiled scenario: {scenario_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
