#!/usr/bin/env python3
import argparse
from pathlib import Path

import numpy as np
from matplotlib import pyplot as plt


def read_traces_from_npz(npz_path: Path, key: str = "traces") -> np.ndarray:
    if not npz_path.exists() or not npz_path.is_file():
        raise FileNotFoundError(f"Fichier introuvable: {npz_path}")

    with np.load(npz_path) as data:
        if key not in data:
            raise KeyError(f"Cle '{key}' absente du fichier NPZ")
        traces = data[key]

    if traces.ndim != 2:
        raise ValueError(f"Format inattendu: tableau 2D attendu, recu {traces.ndim}D")

    return traces


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lit et affiche des traces depuis un fichier NPZ")
    parser.add_argument("npz_file", type=Path, help="Chemin vers le fichier .npz")
    parser.add_argument("--key", default="traces", help="Cle NPZ a lire (par defaut: traces)")
    parser.add_argument("--index", type=int, default=0, help="Index de la trace a afficher")
    parser.add_argument("--no-plot", action="store_true", help="N'affiche pas la courbe")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        traces = read_traces_from_npz(args.npz_file.resolve(), key=args.key)
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(exc)
        return 1

    if args.index < 0 or args.index >= traces.shape[0]:
        print(f"Index invalide: {args.index}, attendu entre 0 et {traces.shape[0] - 1}")
        return 1

    print(f"Traces chargees: shape={traces.shape}, dtype={traces.dtype}")
    print(f"Affichage de la trace #{args.index}")

    if not args.no_plot:
        plt.plot(traces[args.index])
        plt.title(f"Trace #{args.index}")
        plt.xlabel("Sample")
        plt.ylabel("Amplitude")
        plt.show()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
