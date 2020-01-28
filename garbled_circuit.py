# Python 3.7+
from Crypto.Cipher import AES  # pycryptodome
from Crypto.Random.random import shuffle  # pycryptodome
from itertools import product
import secrets


class Wire:
    def __init__(self):
        self.labels = [Wire._make_label(), Wire._make_label()]
        self.evaluated_label = None

    def __iter__(self): return self.labels.__iter__()

    @classmethod
    def _make_label(cls): return secrets.randbits(256).to_bytes(32, 'little')


class Gate:
    def __init__(self, input_wires, output_wire, logic_function):
        self.input_wires, self.output_wire, self.rows = input_wires, output_wire, []
        for entry in product(*map(enumerate, input_wires)):
            function_parameters = [x[0] for x in entry]
            input_labels = [x[1] for x in entry]
            function_value = logic_function(*function_parameters)
            output_label = self.output_wire.labels[function_value]
            self.rows.append(Gate.crypt_row(output_label, input_labels))
        shuffle(self.rows)

    def evaluate(self):
        input_labels = [x.evaluated_label for x in self.input_wires]
        for row in self.rows:
            result = Gate.crypt_row(row, input_labels)
            if result in self.output_wire.labels:
                self.output_wire.evaluated_label = result
                break

    @classmethod  # Symmetric encrypt/decrypt
    def crypt_row(cls, data, keys):
        crypt_data = bytearray(data)
        for key in keys:
            cipher = AES.new(key, AES.MODE_CTR, nonce=b'0', initial_value=0)
            crypt_data = cipher.encrypt(crypt_data)
        return crypt_data


class Circuit:
    def __init__(self, wires, gates):
        self.wires, self.gates = wires, gates

    def get_labels(self, wire_indices):
        return [self.wires[x].labels for x in wire_indices]

    def evaluate(self, input_values):
        for index, value in enumerate(input_values):
            self.wires[index].evaluated_label = value
        for gate in self.gates: gate.evaluate()
        return self.gates[-1].output_wire.evaluated_label


if __name__ == "__main__":  # Standalone demo

    # Generate Z = A*(~B) + (~C)*D
    def generate_circuit():
        wires = [Wire(), Wire(), Wire(), Wire(), Wire(), Wire(), Wire()]  # 4 inputs, 2 internals, 1 output
        gates = [Gate(wires[0:2], wires[4], lambda x, y: x == 1 and y == 0),  # A*(~B)
                 Gate(wires[2:4], wires[5], lambda x, y: x == 0 and y == 1),  # (~C)*D
                 Gate([wires[4], wires[5]], wires[6], lambda x, y: x == 1 or y == 1)]  # OR
        return Circuit(wires, gates)
    circuit = generate_circuit()

    for i, j, k, l in product([0, 1], [0, 1], [0, 1], [0, 1]):
        choices = [x[y] for x, y in zip(circuit.get_labels([0, 1, 2, 3]), [i, j, k, l])]
        x = circuit.evaluate(choices)
        print(i, j, k, l, " : ", circuit.get_labels([6])[0].index(x))
