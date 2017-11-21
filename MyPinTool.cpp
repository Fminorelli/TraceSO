
#include <stdlib.h>
#include <map>
#include <list>
#include <iomanip>
#include <sstream>
#include <utility>
#include <string.h>
#include "pin.H"

#include <iostream>
#include <fstream>
#include "pin.H"
#include <stdio.h>
FILE * trace;
ofstream OutFile;
ifstream testFile;
ofstream teste;
ofstream CFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;
static UINT64 scount = 0;

struct dado {
	int tempo;
	VOID *endereco;
 	char op;
};

vector<dado> dados;


// This function is called before every instruction is executed
VOID RecordMemRead(VOID * ip, VOID * addr)
{

    //fprintf(trace,"%p: R %p\n", ip, addr);
    dado d;
    d.tempo=icount;
    d.endereco=ip;
    d.op ='R';
    dados.push_back(d);
    CFile.setf(ios::showbase);
    CFile << icount <<" "<< ip <<" "<< "R" << endl;
    fprintf(trace, "%li %p: MEMR %p\n",icount,ip,addr);
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{	

	
    //fprintf(trace,"%p: W %p\n", ip, addr);
    dado d;
    d.tempo=icount;
    d.endereco=ip;
    d.op ='W';
    dados.push_back(d);
    CFile.setf(ios::showbase);
    CFile << icount<<" "<< ip <<" "<< "W"<< endl;
    fprintf(trace, "%li %p: MEMW %p\n",icount,ip,addr);
}

VOID PrintSyscall(VOID* ip)
{	
	
	dado d;
    d.tempo=icount;
    d.endereco=ip;
    d.op ='S';
    dados.push_back(d);
    CFile.setf(ios::showbase);
    CFile << icount<< " " << ip <<" "<< "Syscall" << endl;

}

VOID docount() { icount++; }

VOID syscount(VOID* ip) { 
    scount++;
    PrintSyscall(ip); 
}

const char *
dumpInstruction(INS ins)
{
	ADDRINT address = INS_Address(ins);
	std::stringstream ss;

	// Generate instruction byte encoding
	for (size_t i=0;i<INS_Size(ins);i++)
	{
		ss << setfill('0') << setw(2) << hex << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF) << " ";
	}

	for (size_t i=INS_Size(ins);i<8;i++)
	{
		ss << "   ";
	}

	// Generate diassembled string
	ss << INS_Disassemble(ins);

	return strdup(ss.str().c_str());
}


// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{	

	//Conta todas as instruções
	
    //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);

    icount++;
    fprintf(trace, "%li %p: %s\n",icount,(void*) INS_Address(ins),OPCODE_StringShort(INS_Opcode(ins)).c_str());

	//Se for syscall incrementa o contador de syscall
	if(INS_IsSyscall(ins)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscount, IARG_INST_PTR,  IARG_END);
    }


    UINT32 memOperands = INS_MemoryOperandCount(ins);
    if (memOperands == 0){
        //dumpInstruction(ins);
        
    }
    else{

        // Iterate over each memory operand of the instruction.
        for (UINT32 memOp = 0; memOp < memOperands; memOp++)
        {
            if (INS_MemoryOperandIsRead(ins, memOp))
            {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_END);
            }
            // Note that in some architectures a single memory operand can be 
            // both read and written (for instance incl (%eax) on IA-32)
            // In that case we instrument it once for read and once for write.
            else 
            	if (INS_MemoryOperandIsWritten(ins, memOp))
            {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_END);
            }

                else {

            	const char * disasm = dumpInstruction(ins);
            	CFile.setf(ios::showbase);
        		CFile << icount<<" "<< disasm;

        	}
            
        }
    }   

}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");



// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::binary);
    for (unsigned int i = 0; i < dados.size(); ++i)
    {
    	OutFile.write((char*)&dados[i], sizeof(dado));

    }
    
    OutFile << "Syscall Count " << scount << endl;
    OutFile << "Total instruções: " << icount << endl;
    OutFile.close();
    testFile.open(KnobOutputFile.Value().c_str());
    teste.open("saida_mem");
    
    for (unsigned int x = 0; x < dados.size(); ++x)
    {	
    	dado i;
    	testFile.read((char*)&i,sizeof(dado));
    	teste << i.tempo <<" "<< i.endereco<<" "<< i.op << endl;

    }
    testFile.close();
    teste.close();
    CFile.close();
    

    FILE* saida;

    saida = fopen("struct.txt", "w");

    //fwrite(array, dados.size(), sizeof(dado), saida);

    for (unsigned int i = 0; i < dados.size(); ++i)
    {
    	fwrite(&dados[i], sizeof(dado), 1, saida);
    }

    fclose(saida);

    FILE *aaa;

    aaa = fopen("erro", "w");

    fprintf(aaa,"%lu\n", sizeof(char));

    fclose(aaa);
    
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    CFile.open("compare");
    CFile.setf(ios::showbase);
    trace = fopen("saida2.out", "w");


    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    printf("Tamanho i: %lu, total ins: %lu ",dados.size(),icount);
    return 0;
}
