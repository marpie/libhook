
#include "libhook.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdexcept>

#pragma comment(lib, "distorm3.lib") 
#include "extern\distorm3\include\distorm.h"

/**************************************************************************************************
 * Constructor.
 *
 * @author marpie
 * @date 2011-10-21
 *
 * @exception std::runtime_error Thrown when a new Heap couldn't be created.
 *
 * @param src_func  Source function.
 * @param dest_func Destination function.
 **************************************************************************************************/

Hook::Hook(LPVOID src_func, LPVOID dest_func)
{
	hHeap = nullptr;
	saved_instructions_size = 0;
	source_function = src_func;
	saved_instructions = nullptr;
	destination_function = dest_func;

	// create private Heap ... initial size 256 byte
	hHeap = HeapCreate(0, 256, 0);
	if (!hHeap)
		throw std::runtime_error("Couldn't create Heap!");
}

/**************************************************************************************************
 * Destructor.
 *
 * @author marpie
 * @date 2011-10-21
 **************************************************************************************************/

Hook::~Hook()
{
	if (hHeap != NULL)
		HeapDestroy(hHeap);
}

/**************************************************************************************************
 * Returns the byte count of the instructions of at least X bytes (bytes_needed).
 *
 * @author marpie
 * @date 2011-10-21
 *
 * @param bytes_needed		  The bytes needed.
 * @param [in,out] out_buffer If non-null, buffer for output data.
 * @param [in,out] out_size   If non-null, size of the output buffer.
 *
 * @return -1 if an error occured, 0 if the output_buffer is too small otherwise the size of the
 *  instructions (bytes_needed).
 **************************************************************************************************/

int Hook::getCompleteInstructions(const int bytes_needed, char *out_buffer, int *out_size)
{
	if ((bytes_needed == 0) || !source_function)
		return -1;

	_DInst *decodedInstructions = nullptr;
	unsigned int decodedInstructionsCount = 0;

	decodedInstructions = static_cast<_DInst *>(HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bytes_needed*sizeof(_DInst)));
	if (!decodedInstructions)
		return -1;

	// Dissasamble the function ...
	_CodeInfo ci;
	ci.code = reinterpret_cast<const uint8_t *>(source_function);
	ci.codeLen = bytes_needed*2;
	ci.codeOffset = 0;
#if defined(_X86_)	// Defined on the command line by a linker variable.
    // the target architecture is x86
	ci.dt = Decode32Bits;
#elif defined(_AMD64_)
    // the target architecture is AMD x86-64
	ci.dt = Decode64Bits;
#endif
	ci.features = DF_NONE;
	distorm_decompose(&ci, decodedInstructions, bytes_needed, &decodedInstructionsCount);

	// Get the size of the fewest instructions ... bytes_needed <= instruction_size
	int current_size = 0;
	for (int i = 0; i < bytes_needed; ++i)
	{
		if (current_size < bytes_needed)
			current_size += (decodedInstructions+i)->size;
		else
			break;
	}

	HeapFree(hHeap, 0, decodedInstructions);

	if (!out_buffer || (*out_size < current_size))
	{
		// Not enough space in output buffer
		*out_size = current_size;
		return 0;
	}

	CopyMemory(out_buffer, reinterpret_cast<void *>(source_function), current_size);

	return current_size;
}

/**************************************************************************************************
 * Saves the first instructions of the source_function to the variable saved_instructions.
 *
 * @author marpie
 * @date 2011-10-21
 *
 * @param size_needed The size needed for the replacement code.
 *
 * @return true if it succeeds, false if it fails.
 **************************************************************************************************/

bool Hook::saveInstructions(const int size_needed)
{
	if (saved_instructions != NULL)
		return false;

	if (getCompleteInstructions(size_needed, nullptr, &saved_instructions_size) != 0)
	{
		saved_instructions_size = 0;
		return false;
	}

	// allocate size for the instructions saved of the original function
	saved_instructions = static_cast<char *>(HeapAlloc(hHeap, 0, saved_instructions_size));
	if (saved_instructions == NULL)
	{
		saved_instructions_size = 0;
		return false;
	}

	// copy the instructions to the saved_instructions buffer
	if (getCompleteInstructions(size_needed, saved_instructions, &saved_instructions_size) != saved_instructions_size)
	{
		saved_instructions_size = 0;
		return false;
	}

	return true;
}

/**************************************************************************************************
 * Frees the saved instructions var.
 *
 * @author marpie
 * @date 2011-10-21
 *
 **************************************************************************************************/

void Hook::freeSaveInstructions(void)
{
	if (saved_instructions != NULL)
		HeapFree(hHeap, 0, saved_instructions);
	saved_instructions = nullptr;
	saved_instructions_size = 0;
}
