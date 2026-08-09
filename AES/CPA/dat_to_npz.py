#!/usr/bin/env python3
import argparse
from pathlib import Path

import numpy as np
from lecroyscope import Trace


def resolve_output_file(output_path: Path) -> Path:
    if output_path.exists() and output_path.is_dir():
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path / "traces.npz"

    if output_path.suffix.lower() != ".npz":
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path / "traces.npz"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def convert_dat_to_npz(input_dir: Path, output_file: Path, compress: bool) -> int:
    dat_files = sorted(input_dir.rglob("*.dat"))
    if not dat_files:
        print(f"Aucun fichier .dat trouve dans {input_dir}")
        return 1

    blocks = []
    nb_samples = None

    for dat_file in dat_files:
        raw_traces = Trace(str(dat_file)).adc_values.astype(np.int16)
        if raw_traces.ndim != 2:
            print(f"Ignore (format inattendu): {dat_file}")
            continue

        if nb_samples is None:
            nb_samples = raw_traces.shape[1]

        block = np.zeros((raw_traces.shape[0], nb_samples), dtype=np.int16)
        n = min(raw_traces.shape[1], nb_samples)
        block[:, :n] = raw_traces[:, :n]
        blocks.append(block)
        print(f"Charge: {dat_file} ({raw_traces.shape[0]} traces)")

    if not blocks:
        print("Aucune trace valide a sauvegarder.")
        return 1

    traces = np.vstack(blocks)

    if compress:
        np.savez_compressed(output_file, traces=traces)
    else:
        np.savez(output_file, traces=traces)

    print(f"Termine: {len(blocks)} fichier(s) agrege(s) -> {output_file}")
    print(f"Shape final: {traces.shape}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convertit des fichiers .dat Lecroy en .npz")
    parser.add_argument(
        "input_dir",
        type=Path,
        help="Dossier d'entree contenant les fichiers .dat",
    )
    parser.add_argument(
        "output_path",
        type=Path,
        nargs="?",
        default=Path("traces.npz"),
        help="Fichier .npz de sortie, ou dossier (par defaut: ./traces.npz)",
    )
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Desactive la compression (utilise np.savez)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output_file = resolve_output_file(args.output_path.resolve())

    if not input_dir.exists() or not input_dir.is_dir():
        print(f"Dossier d'entree invalide: {input_dir}")
        return 1

    return convert_dat_to_npz(input_dir, output_file, compress=not args.no_compress)


if __name__ == "__main__":
    raise SystemExit(main())
