# COFF
from struct import *


class Relocation:
    CoffObject= None
    SectionName =""
    Index=0
    def __init__(self,CoffObject,SectionName,Index):
        self.Index = Index
        self.SectionName = SectionName
        self.CoffObject = CoffObject
    def GetOffset(self):
        return self.CoffObject.get(self.SectionName + ".Relocation." + str(self.Index)  + ".r_vaddr")
    def GetType(self):
        return self.CoffObject.get(self.SectionName + ".Relocation." +str(self.Index)  + ".r_type")
    def GetSybmol(self):
        Index = self.CoffObject.get(self.SectionName + ".Relocation." +str(self.Index)  + ".r_symndx")
        return self.CoffObject.get( "Symbol." + str(Index) + ".e")
    def GetSection(self):
        Indexs = self.CoffObject.get(self.SectionName + ".Relocation." + str(self.Index) + ".r_symndx")
        #print(Indexs)
        SectionIndex = self.CoffObject.get("Symbol." + str(Indexs) + ".e_scnum")
        if SectionIndex ==0:
            return ""
        elif SectionIndex ==-1:
            return "<e_value is a constant>"
        elif SectionIndex ==-2:
            return "<debug symbol>"
        else:
            for i in range(len(self.CoffObject.SectionsTable)):
                if SectionIndex == i:
                    return self.CoffObject.SectionsTable[i-1]
            return "<unknown>"
    def getOffsetInSection(self):
        Index = self.CoffObject.get(self.SectionName + ".Relocation." + str(self.Index) + ".r_symndx")
        return self.CoffObject.get("Symbol." + str(Index) + ".e_value")
    def toString(self):
        StringBuffer = []
        if self.GetType() == 6:
            StringBuffer.append("RELOC_ADDR32")
        elif self.GetType() == 20:
            StringBuffer.append("RELOC_REL32")
        elif self.GetType() == 4:
            StringBuffer.append("RELOC64_REL32")
        else:
            StringBuffer.append("RELOC_UNK_"+str(self.GetType()))
        StringBuffer.append(" ")
        StringBuffer.append(str(self.GetOffset()))
        StringBuffer.append(" 0x")
        StringBuffer.append(hex((self.GetOffset())))
        StringBuffer.append(" ")
        StringBuffer.append(self.GetSybmol())
        StringBuffer.append(" (")
        StringBuffer.append(self.GetSection())
        if self.GetSection() == "":
            StringBuffer.append(")")
        else:
            StringBuffer.append(",")
            StringBuffer.append(str(self.getOffsetInSection()))
            StringBuffer.append(" 0x")
            StringBuffer.append(hex(self.getOffsetInSection()))
            StringBuffer.append(")")
        return "".join(StringBuffer)




class COFFHandle:
    epcfunc = "go"
    ReadOffset = 0
    data = b""
    DataDirectory = {}
    Sections = 0
    TimeDateStamp = 0
    PointerToSymbolTable = 0
    NumberOfSymbols = 0
    SizeOfOptionalHeader = 0
    Characteristics = 0
    DataSturct = {}
    locations = {}
    SectionsTable = []
    OldOffset = 0
    exesect = ""
    SectionsCharacter = {}
    stack = []
    isX64 = False

    def __init__(self, CoffData):  # Constructor
        self.data = CoffData
        self.Process()

    def jump(self, Offset):  # Jump to a specific offset and record a layer
        self.stack.append(self.ReadOffset)
        self.ReadOffset = Offset

    def complete(self):  # return layer
        self.ReadOffset = self.stack.pop()

    def consume(self, Offset):  # increase offset
        self.ReadOffset += Offset

    def ReadData(self, Size):  # read fixed length data
        self.ReadOffset += Size
        return self.data[self.ReadOffset - Size:self.ReadOffset]

    def ReadShort(self):  # read 2-byte unsigned integer
        return unpack("H", self.ReadData(2))[0]

    def ReadInt(self):  # read 4-byte unsigned integer
        return unpack("I", self.ReadData(4))[0]

    def ReadChar(self):  # read single byte
        return self.ReadData(1)

    def ReadByte(self):  # read single byte  of unsigned integer
        return unpack("B", self.ReadData(1))[0]

    def ReadString(self):  # Read the string with 00 as the end character
        StrngBuffer = []
        while True:
            Char = self.ReadChar()
            if unpack("B", Char[:1])[0] <= 0:
                return b"".join(StrngBuffer).decode()
            StrngBuffer.append(Char)

    def ReadStrings(self, Size):  # read string with length
        StrngBuffer = []
        for i in range(Size):
            Char = self.ReadChar()

            if unpack("B", Char)[0] > 0:
                StrngBuffer.append(Char)
        return b"".join(StrngBuffer).decode()

    def strstr(self, line):  # string truncation
        StringBuffer = []
        for i in line:
            if i == "\x00":
                return "".join(StringBuffer)
            StringBuffer.append(i)
        return "".join(StringBuffer)

    def report(self, Name):  # the sign
        self.locations.update({Name: self.ReadOffset})

    def put(self, Name, Value):  # Put the data into the data structure
        self.DataSturct.update({Name: Value})

    def get(self, Name):  # Get a specific index value from a data structure
        return self.DataSturct.get(Name)

    def readCharacteristics(self, SectionName):  # Read data compiled attributes (permissions)
        Character = self.ReadInt()
        Characteristics = []
        if (Character & 32) == 32:
            Characteristics.append("Code")
        if (Character & 64) == 64:
            Characteristics.append("Initialized Data")
        if (Character & 128) == 128:
            Characteristics.append("Uninitialized Data")
        if (Character & 67108864) == 67108864:
            Characteristics.append("Section cannot be cached")
        if (Character & 134217728) == 134217728:
            Characteristics.append("Section is not pageable")
        if (Character & 268435456) == 268435456:
            Characteristics.append("Section is shared")
        if (Character & 536870912) == 536870912:
            Characteristics.append("Executable")
        if (Character & 1073741824) == 1073741824:
            Characteristics.append("Readable")
        if (Character & 2147483648) == 2147483648:
            Characteristics.append("Writable")
        if (Character & 536870912) == 536870912:
            self.exesect = SectionName
        Characteristics.append("0x%x" % Character)
        self.SectionsCharacter.update({f"{SectionName}.Characteristics": Characteristics})

    def readRelocation(self, SectionName, Index):  # read redirect table
        r_vaddr = self.ReadInt()
        r_symndx = self.ReadInt()
        r_type = self.ReadShort()
        self.put(SectionName + ".Relocation." + str(Index) + ".r_vaddr", r_vaddr);
        self.put(SectionName + ".Relocation." + str(Index) + ".r_symndx", r_symndx);
        self.put(SectionName + ".Relocation." + str(Index) + ".r_type", r_type);

    def parseRelocations(self, SectionName):  # read redirect
        NumberOfRelocations = self.get(f"{SectionName}.NumberOfRelocations")
        PointerToRelocations = self.get(f"{SectionName}.PointerToRelocations")
        self.jump(PointerToRelocations)
        for i in range(NumberOfRelocations):
            self.readRelocation(SectionName, i)
        self.complete()

    def parseSection(self, i):  # read segment offset
        self.report(f"Sections.AddressOfName.{i}")
        SectionName = self.strstr(self.ReadData(8).decode(encoding="utf-8"))
        self.SectionsTable.append(SectionName)
        self.put(f"{SectionName}.VirtualSize", self.ReadInt())
        self.put(f"{SectionName}.VirtualAddress", self.ReadInt())
        self.put(f"{SectionName}.SizeOfRawData", self.ReadInt())
        self.put(f"{SectionName}.PointerToRawData", self.ReadInt())
        self.put(f"{SectionName}.PointerToRelocations", self.ReadInt())
        self.put(f"{SectionName}.PointerToLinenumbers", self.ReadInt())
        self.put(f"{SectionName}.NumberOfRelocations", self.ReadShort())
        self.put(f"{SectionName}.NumberOfLinenumbers", self.ReadShort())
        self.readCharacteristics(SectionName)
        self.parseRelocations(SectionName)

    def readStringTableOffset(self, Offset):  # read a specific offset string
        self.jump(self.PointerToSymbolTable + (self.NumberOfSymbols * 18))
        self.consume(Offset)
        Data = (self.ReadString())
        self.complete()
        return Data

    def readSymbolName(self):  # get symbol table name
        self.jump(self.ReadOffset)
        Data = self.ReadInt()
        self.complete()
        if (Data == 0):
            self.consume(4)
            Offset = self.ReadInt()
            return self.readStringTableOffset(Offset)
        else:
            return self.ReadStrings(8)

    def parseSymbol(self, Index):  # Get symbol table information
        self.put(f"Symbol.{Index}.e", self.readSymbolName())
        self.put(f"Symbol.{Index}.e_value", self.ReadInt())
        self.put(f"Symbol.{Index}.e_scnum", self.ReadShort())
        self.put(f"Symbol.{Index}.e_type", self.ReadShort())
        self.put(f"Symbol.{Index}.e_sclass", self.ReadByte())
        self.put(f"Symbol.{Index}.e_numaux", self.ReadByte())
        if self.get(f"Symbol.{Index}.e_sclass") == 103:
            self.put(f"Symbol.{Index}.e_auxval", self.ReadStrings(18))
        elif self.get(f"Symbol.{Index}.e_numaux") > 0:
            self.consume(18 * self.get(f"Symbol.{Index}.e_numaux"))

    def parseSymbols(self):  # Get symbol table information
        NumberOfSymbols = self.NumberOfSymbols
        x = 0
        for i in range(NumberOfSymbols):
            if NumberOfSymbols == x:
                break
            self.parseSymbol(x)
            x += self.get(f"Symbol.{x}.e_numaux")
            x += 1

    def Process(self):  # core function
        self.Machine = self.ReadShort()  # Identify the Machine flag in the file header
        if self.Machine == 332:  # x86 object file
            self.isX64 = False
        elif self.Machine == 34404:  # x64 object file
            self.isX64 = True
        else:  # Validation failed
            print("Invalid Machine header value :%d" % self.Machine)
            return
        self.Sections = self.ReadShort()  # Identify the number of Sections
        self.TimeDateStamp = self.ReadData(4);
        self.PointerToSymbolTable = self.ReadInt()  # Symbol table pointer offset
        self.NumberOfSymbols = self.ReadInt()
        self.SizeOfOptionalHeader = self.ReadShort()
        Characteristics = self.ReadShort()
        for i in range(self.Sections):
            self.parseSection(i)
        self.jump(self.PointerToSymbolTable)
        self.parseSymbols()

    def relocationsCount(self,Name):
        return self.get(f"{Name}.NumberOfRelocations")

    def getRelocation(self,Name,Index):
        return Relocation(self,Name,Index)
    def findInternalFunction(self,Functionname):
        APIList = ['LoadLibraryA', 'FreeLibrary', 'GetProcAddress', 'GetModuleHandleA', 'BeaconDataParse', 'BeaconDataPtr',
         'BeaconDataInt', 'BeaconDataShort', 'BeaconDataLength', 'BeaconDataExtract', 'BeaconFormatAlloc',
         'BeaconFormatReset', 'BeaconFormatAppend', 'BeaconFormatPrintf', 'BeaconFormatToString', 'BeaconFormatFree',
         'BeaconFormatInt', 'BeaconOutput', 'BeaconPrintf', 'BeaconErrorD', 'BeaconErrorDD', 'BeaconErrorNA',
         'BeaconUseToken', 'BeaconRevertToken', 'BeaconIsAdmin', 'BeaconGetSpawnTo', 'BeaconInjectProcess',
         'BeaconInjectTemporaryProcess', 'BeaconSpawnTemporaryProcess', 'BeaconCleanupProcess', 'toWideChar']
        try:
            Functionname = Functionname.split("@")[0];
        except:
            pass
        Count  = 0
        for name in APIList:
            Api__imp__Name = "__imp__"+name
            Api__imp_Name = "__imp_"+name
            if Functionname == Api__imp__Name or Functionname == Api__imp_Name:
                return Count
            Count+=1
        return -1
    def isInternalFunction(self,Name):
        return self.findInternalFunction(Name)>=0

    def sectionStart(self,Section):
        return self.get(Section + ".PointerToRawData");
    def sectionSize(self,Section):
        return self.get(Section + ".SizeOfRawData");
    def getEntryPoint(self):
        NumberOfSymbols = self.NumberOfSymbols
        for i in range(NumberOfSymbols):
            E = self.get("Symbol." + str(i) + ".e");
            if "_"+self.epcfunc == E or self.epcfunc == E:
                return self.get("Symbol." + str(i) + ".e_value");
        print("Entry function '" + self.epfunc + "' is not defined.")
        return 0
    def getCode(self):
        Start = self.sectionStart(self.exesect)
        Sizes = self.sectionSize(self.exesect)
        if Sizes == 0:
            print("No .text section in object file")
        self.jump(Start)
        return self.ReadData(Sizes)
    def getRData(self):
        Start = self.sectionStart(".rdata")
        Sizes = self.sectionSize(".rdata")
        self.jump(Start)
        return self.ReadData(Sizes)
    def getData(self):
        Start = self.sectionStart(".data")
        Sizes = self.sectionSize(".data")
        self.jump(Start)
        return self.ReadData(Sizes)

    def getRelocations(self):
        RelocationPareater = Pareater()
        for i in range(8*4096):
            if i+1>self.relocationsCount(self.exesect):
                break
            Pack = Packet()
            RelocationObject  = self.getRelocation(self.exesect,i)
            if RelocationObject.GetSection() == ".rdata":
                Pack.AddShort(RelocationObject.GetType())
                Pack.AddShort(1024)
                Pack.AddInt(RelocationObject.GetOffset())
                Pack.AddInt(RelocationObject.getOffsetInSection())
            elif RelocationObject.GetSection() == ".data":
                print(RelocationObject.GetType())
                Pack.AddShort(RelocationObject.GetType())
                Pack.AddShort(1025)
                Pack.AddInt(RelocationObject.GetOffset())
                Pack.AddInt(RelocationObject.getOffsetInSection())
            elif RelocationObject.GetSection() == self.exesect:
                Pack.AddShort(RelocationObject.GetType())
                Pack.AddShort(1026)
                Pack.AddInt(RelocationObject.GetOffset())
                Pack.AddInt(RelocationObject.getOffsetInSection())
            elif self.isInternalFunction(RelocationObject.GetSybmol()):
                Pack.AddShort(RelocationObject.GetType())
                Pack.AddShort(self.findInternalFunction(RelocationObject.GetSybmol()))
                Pack.AddInt(RelocationObject.GetOffset())
                Pack.AddInt(0)
            else:
                print("Unknown symbol '" + RelocationObject.GetSybmol() + "'");
            RelocationPareater.AddPareater(PAREATER_MEMORY,Pack.GetBuffer())
        Pack = Packet()
        Pack.AddShort(0);
        Pack.AddShort(1028);
        Pack.AddInt(0);
        Pack.AddInt(0);
        RelocationPareater.AddPareater(PAREATER_MEMORY, Pack.GetBuffer())
        return RelocationPareater.GetBuffer()

class Packet:
    Buffer = b""

    def __init__(self):
        pass
    def GetBuffer(self):
        return self.Buffer
    def Length(self):
        return len(self.Buffer)
    def AddShort(self,Data):
        self.Buffer += pack("H",Data)
    def AddInt(self,Data):
        self.Buffer += pack("I", Data)
    def AddWord(self,Data):
        self.Buffer += pack("B", Data)
    def AddBytes(self,Data):
        self.Buffer += Data
    def AddString(self,Data):
        self.Buffer += Data.encode()

class Pareater: 
    PareaterList={}
    Count=0
    def __init__(self):
        pass
    def AddPareater(self,Type,Data):
        StructBuffer= Packet()
        StructBuffer.AddInt(len(Data))
        StructBuffer.AddInt(Type)
        StructBuffer.AddBytes(Data)
        self.PareaterList.update({self.Count:StructBuffer})
        self.Count+=1
    def GetBuffer(self):
        Buffer = Packet()
        for i in range(len(self.PareaterList.keys())):
            PacketObject = self.PareaterList[i]
            Buffer.AddBytes(PacketObject.GetBuffer())
        TotalIndex = len(self.PareaterList.keys())
        TotalSize  = len(Buffer.GetBuffer())
        PacketBuffer = Packet()
        PacketBuffer.AddInt(TotalIndex)
        PacketBuffer.AddInt(TotalSize)
        PacketBuffer.AddBytes(Buffer.GetBuffer())
        return PacketBuffer.GetBuffer()

PAREATER_MEMORY   =  0
PAREATER_INTERGER =  1
PAREATER_STRING   =  2

if __name__ == "__main__":
    COFF = open("hello.o", "rb").read()
    CoffObject = COFFHandle(COFF)
    CoffObject.getEntryPoint()
    Par = Pareater()
    Par.AddPareater(PAREATER_INTERGER,pack("I",CoffObject.getEntryPoint()))
    Par.AddPareater(PAREATER_MEMORY,CoffObject.getCode())
    Par.AddPareater(PAREATER_MEMORY,CoffObject.getRData())
    Par.AddPareater(PAREATER_MEMORY,CoffObject.getData())
    Par.AddPareater(PAREATER_MEMORY,CoffObject.getRelocations())
    Argvs  = Pareater()
    Argvs.AddPareater(PAREATER_MEMORY,b"String")
    Par.AddPareater(PAREATER_MEMORY,Argvs.GetBuffer())
    Par.GetBuffer()
