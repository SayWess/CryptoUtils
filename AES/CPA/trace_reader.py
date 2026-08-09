from lecroyscope import Trace
from matplotlib import pyplot as plt
import os
import numpy as np


def read_traces_from_file(file_path):
    trace = Trace(file_path)
    return trace.adc_values


def read_traces_from_directory(directory, max_files=None):
    print('Chargement des traces ...')
    file_list = sorted([
        os.path.join(directory, filename)
        for filename in os.listdir(directory)
        if filename.endswith(".dat") and os.path.isfile(os.path.join(directory, filename))
    ])
    first_traces = read_traces_from_file(file_list[0])
    nb_per_file = first_traces.shape[0]
    nb_samples = first_traces.shape[1]
    nb_traces = len(file_list) * nb_per_file
    traces = np.zeros((nb_traces, nb_samples), dtype=np.int16)

    for f, file in enumerate(file_list):
        file_traces = read_traces_from_file(file)
        for i, trace in enumerate(file_traces):
            n = min(len(trace), nb_samples)
            traces[i + f * nb_per_file, :n] = trace[:n].astype(np.int16)

    print(f"Traces chargées")
    return traces

traces = read_traces_from_directory("404_EM")

plt.plot(traces[0])
plt.show()
