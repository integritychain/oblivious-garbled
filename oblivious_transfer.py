import hashlib, secrets
from itertools import product
from garbled_circuit import Wire, Gate, Circuit

# Assume each transfer is a 256-bytestring 'label'
# Chooser for each choice: provide a key and get a message

def make_label(): return secrets.randbits(256).to_bytes(32, 'little')


# See RFC 5114 Additional Diffie-Hellman Groups for Use with IETF Standards at https://tools.ietf.org/html/rfc5114#section-2.1
PRIME = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
GENERATOR = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
ORDER = 0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353
assert pow(GENERATOR, ORDER, PRIME) == 1


class Sender:
    def __init__(self):
        self.C = pow(GENERATOR, secrets.randbits(256), PRIME)
        self.circuit = None

    def publish_c(self): return self.C

    def deliver_circuit(self, two_choices):
        wires = [Wire(), Wire(), Wire(), Wire(), Wire(), Wire(), Wire()]  # 4 inputs, 2 internals, 1 output
        gates = [Gate(wires[0:2], wires[4], lambda x, y: x == 1 and y == 0),  # A*(~B)
                 Gate(wires[2:4], wires[5], lambda x, y: x == 0 and y == 1),  # (~C)*D
                 Gate([wires[4], wires[5]], wires[6], lambda x, y: x == 1 or y == 1)]  # OR
        self.circuit = Circuit(wires, gates)
        return self.circuit, wires[0].labels[two_choices[0]], wires[1].labels[two_choices[1]]

    def deliver_ot(self, public_keys):
        response = []
        labels_for_chooser = [self.circuit.wires[2].labels, self.circuit.wires[3].labels]
        for index, public_key0 in enumerate(public_keys):
            inverse0 = pow(public_key0, PRIME - 2, PRIME)
            public_key1 = self.C * inverse0 % PRIME
            assert public_key0 * public_key1 % PRIME == self.C  # what if pk0 == C?

            enc_0 = bytearray(labels_for_chooser[index][0])
            r0 = secrets.randbits(128)
            gr0 = pow(GENERATOR, r0, PRIME)
            pk0r0 = pow(public_key0, r0, PRIME).to_bytes(128, 'little')
            for i, byte_val in enumerate(hashlib.sha256(pk0r0).digest()): enc_0[i] ^= byte_val

            enc_1 = bytearray(labels_for_chooser[index][1])
            r1 = secrets.randbits(128)
            gr1 = pow(GENERATOR, r1, PRIME)
            pk1r1 = pow(public_key1, r1, PRIME).to_bytes(128, 'little')
            for i, byte_val in enumerate(hashlib.sha256(pk1r1).digest()): enc_1[i] ^= byte_val

            response.append(((gr0, enc_0), (gr1, enc_1)))
        return response

class Chooser:

    def __init__(self, C, choices):
        self.choices = choices # contains a list of zeros and ones (e.g. gimme zero label or one label)
        self.labels = []
        self.public_keys = []
        self.ks = []
        for index, choice in enumerate(self.choices):
            pk = [[],[]]
            k = secrets.randbits(256)
            pk[choice] = pow(GENERATOR, k, PRIME)
            inverse = pow(pk[choice], PRIME - 2, PRIME)
            pk[1 - choice] = inverse * C % PRIME
            self.public_keys.append(pk)
            self.ks.append(k)

    def get_public_keys(self):
        return [pk[0] for pk in self.public_keys]

    def ingest_labels(self, labels):
        result = []
        for i, choice in enumerate(self.choices):
            gr, msg = labels[i][0] if choice == 0 else labels[i][1]
            grk0 = pow(gr, self.ks[i], PRIME).to_bytes(128, 'little')
            dec_w0 = bytearray(msg)
            for index, byte_val in enumerate(hashlib.sha256(grk0).digest()): dec_w0[index] ^= byte_val
            #print("i={} wanted={} label={}".format(i, choice, dec_w0.hex()))
            result.append(dec_w0)
        return result


if __name__ == "__main__":  # Standalone demo

    for i, j, k, l in product([0, 1], [0, 1], [0, 1], [0, 1]):

        sender = Sender()
        c = sender.publish_c()
        circuit, label0, label1 = sender.deliver_circuit([i, j])


        chooser = Chooser(c, [k, l])

        pks = chooser.get_public_keys()

        enc_labs = sender.deliver_ot(pks)

        dec_labs = chooser.ingest_labels(enc_labs)

        x = circuit.evaluate([label0, label1, dec_labs[0], dec_labs[1]])
        print(i, j, k, l, " : ", circuit.get_labels([6])[0].index(x))

