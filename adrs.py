class ADRS:
    """
    ADRS is a 32-byte address, consists of 4-byte chuncks

    layer address   4  bytes [0:4]      height of the XMSS tree in the hypertree
    tree address    12 bytes [4:16]     position of the XMSS tree
    type            4  bytes [16:20]    ADRS type, see above
    special data    12 bytes [20:32]    special data, changes depending on the type
    """
    def __init__(self):
        self._adrs = self.toByte(0, 32)

    def getADRS(self):
        return self._adrs

    # algorithm 2
    @staticmethod
    def toInt(X, n):
        total = 0
        for i in range(n):
            total = 256 * total + X[i]
        return total

    # algorithm 3
    @staticmethod
    def toByte(x, n):
        total = x
        S = [0 for _ in range(n)]
        for i in range(n):
            S[n-1-i] = total % 256
            total = total >> 8
        return S

    # functions according to Table 1
    def setLayerAddress(self, l):
        self._adrs[0:4] = self.toByte(l, 4)

    def setTreeAddress(self, t):
        self._adrs[4:16] = self.toByte(t, 12)

    def setTypeAndClear(self, Y):
        self._adrs[16:20] = self.toByte(Y, 4)
        self._adrs[20:32] = self.toByte(0, 12)

    def setKeyPairAddress(self, i):
        self._adrs[20:24] = self.toByte(i, 4)
    
    def setChainAddress(self, i):
        self._adrs[24:28] = self.toByte(i, 4)

    def setTreeHeight(self, i):
        self._adrs[24:28] = self.toByte(i, 4)

    def setHashAddress(self, i):
        self._adrs[28:32] = self.toByte(i, 4)

    def setTreeIndex(self, i):
        self._adrs[28:32] = self.toByte(i, 4)

    def getKeyPairAddress(self):
        return self.toInt(self._adrs[20:24], 4)

    def getTreeIndex(self):
        return self.toInt(self._adrs[28:32], 4)
