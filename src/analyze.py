import pandas as pd
import csv
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re

def extract_vals(names: list, file_path: str):
    """ TODO """
    with open(file_path, mode="r") as f:
        data = f.read().split("\n")

    return [
        np.array([float(row.split(",")[1]) for row in data if row.split(",")[0] == name])
        for name in names
    ]


def create_box_plot(values, labels, outname, title='Box Plot', xlabel='X-axis', ylabel='Values'):
    plt.figure(figsize=(12, 16))
    plt.boxplot(values, labels=labels)
    plt.title(title)
    plt.xlabel('Name')
    plt.ylabel('Time')
    plt.savefig(outname, bbox_inches='tight')
    plt.close()


class CSVFunctionComparator:
    def __init__(self, file1, file2):
        self.file1 = file1
        self.file2 = file2
        self.data1 = None
        self.data2 = None

    def load_data(self):
        # Assumes first column is function name, second column is value
        self.data1 = pd.read_csv(self.file1)
        self.data2 = pd.read_csv(self.file2)

    def extract_and_clean(self):
        # Group by function and collect values as lists, remove outliers using IQR
        def clean_func(df):
            def convert_value(val):
                # Convert values to microseconds and extract numerical part
                match = re.match(r"([\d.]+)(ms|µs)", val)
                if not match:
                    return None  # Handle invalid formats if needed
                num, unit = match.groups()
                num = float(num)
                return num * 1000 if unit == 'ms' else num

            # Create a copy to avoid modifying original dataframe
            df = df.copy()
            df['value'] = df['value'].apply(convert_value)

            result = {}
            for func, group in df.groupby('function_name'):
                values = group['value'].astype(float).tolist()
                # Remove outliers using IQR
                q1 = pd.Series(values).quantile(0.25)
                q3 = pd.Series(values).quantile(0.75)
                iqr = q3 - q1
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                cleaned = [v for v in values if lower <= v <= upper]
                if cleaned:
                    result[func] = cleaned
            return result
        self.cleaned1 = clean_func(self.data1)
        self.cleaned2 = clean_func(self.data2)

    def compare_and_plot(self):
        # Store sum, mean and std for each algorithm
        results_classic = []
        results_quantum = []

        # Find common function names
        common_funcs = set(self.cleaned1.keys()).intersection(self.cleaned2.keys())
        for func in common_funcs:
            data = [self.cleaned1[func], self.cleaned2[func]]
            plt.figure()
            plt.boxplot(data, labels=['Classic', 'Quantum'])
            plt.title(f"Boxplot Comparison for '{func}'")
            plt.ylabel("Time")
            plt.xlabel("Name")
            plt.savefig(f"/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/bplots/{func.replace(':','')}.png", bbox_inches='tight')
            plt.close()

            _sum = sum(self.cleaned1[func])
            mean = np.mean(self.cleaned1[func])
            std_dev = np.std(self.cleaned1[func])
            results_classic.append([func, _sum, mean, std_dev])

            _sum = sum(self.cleaned2[func])
            mean = np.mean(self.cleaned2[func])
            std_dev = np.std(self.cleaned2[func])
            results_quantum.append([func, _sum, mean, std_dev])

        # Save statistics into the output CSV file
        classic_output = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/classic_output.csv'
        quantum_output = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/quantum_output.csv'

        with open(classic_output, mode='w', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['function_name', 'sum', 'mean', 'std_dev'])
            writer.writerows(results_classic)

        with open(quantum_output, mode='w', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['function_name', 'sum', 'mean', 'std_dev'])
            writer.writerows(results_quantum)

    def run(self):
        self.load_data()
        self.extract_and_clean()
        self.compare_and_plot()

# generate_ntor_keys for quantum is generate_kyber_keys and for classic is generage_curve_keys
# QuantumNtorTcp::new and ClassicNtorTcp::new -> NTorTcp::new
functions_names = ["generate_rsa_keys", "generate_ntor_keys",
                           "NtorTcp::new", "ServerNode::new",
                           "ClientNode::new", "ClientSide::new",
                           "ClientNode::sent_to_server", "ServerNode::deserializing",
                           "ServerNode::handle_client", "ServerSide::new",
                           "ServerSide::send_to_client", "ServerNode::send_to_client",
                           "ClientNode::deserializing", "ClientNode::handle_server",
                           "ClientSide::client_ckeck","NtorTcp::ntor"
                           ]

classic_input = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/classic.csv'
quantum_input = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/quantum.csv'
classic_output = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/classic_output.csv'
quantum_output = '/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/quantum_output.csv'

# Without outliers
comparator = CSVFunctionComparator(classic_input, quantum_input)
comparator.run()

# With outliers
"""for name in functions_names_classic:
    idx = functions_names_classic.index(name)
    create_box_plot(
        [classic_vals[idx], quantum_vals[idx]],
        ['Classic', 'Quantum'],
        f"/Users/monaayati/Computer-Science-Master/Work/rust/project/qsntor/bplots/{name.replace(':','')}.png",
        title=name + "/" + functions_names_quantum[idx]
    )
"""
