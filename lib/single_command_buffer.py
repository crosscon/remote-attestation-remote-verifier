class SingleCommandBuffer():

    def __init__(self):
        self.__lines = []
        self.__half_cmd = bytes()


    def update(self, bs: bytes) -> None:
        for b in bs:
            b = bytes([b])
            if b == b"\n":
                self.__lines.append(self.__half_cmd)
                self.__half_cmd = bytes()
            else:
                self.__half_cmd += b


    def has_command(self) -> bool:
        return b"" in self.__lines


    def get_next_command(self) -> list[bytes] | None:
        if not self.has_command():
            return None

        i = 0
        while self.__lines[i] != b"":
            i += 1

        r = self.__lines[:i]
        self.__lines = self.__lines[i+1:]
        return r


    def check(self) -> None:
        print(b"" in self.__lines)
        print(self.__lines)
        print(self.__half_cmd)

