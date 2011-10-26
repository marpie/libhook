/**************************************************************************************************
 * @file hook_traditional.cpp
 *
 * Implements the traditional hooking class. 
 **************************************************************************************************/

#include "libhook.h"

/**************************************************************************************************
 * Applies the hook.
 *
 * @author marpie
 * @date 2011-10-21
 *
 * @return true if it succeeds, false if it fails.
 **************************************************************************************************/

bool HookTraditional::ApplyHook(void)
{
	if (!saveInstructions(JUMP_PATCH_SIZE))
		return false;

	// set up jmp variable -- BEGIN ///////////////////////////////////////////
	// 
	// allocate memory for jmp var
	patch = reinterpret_cast<char *>(HeapAlloc(hHeap, 0, saved_instructions_size));
	if (!patch)
	{
		freeSaveInstructions();
		return false;
	}

#if defined(_X86_)	// Defined on the command line by a linker variable.
    // the target architecture is x86
	UINT32 jmp_target = reinterpret_cast<UINT32>(destination_function);
#elif defined(_AMD64_)
    // the target architecture is AMD x86-64
	UINT64 jmp_target = reinterpret_cast<UINT64>(destination_function);
#endif

	// prepare patch
	CopyMemory(patch, &JUMP_PATCH, JUMP_PATCH_SIZE);
	// replace address
	CopyMemory(patch+JUMP_LOCATION, &jmp_target, sizeof(jmp_target));

	// insert nop sled if needed
	if (JUMP_PATCH_SIZE < saved_instructions_size)
		FillMemory(patch+JUMP_PATCH_SIZE, saved_instructions_size-JUMP_PATCH_SIZE, NOP_CODE);
	//
	// set up jmp variable -- END /////////////////////////////////////////////

	// enable write access to the location to patch
	DWORD oldProtect = 0;
	if (!VirtualProtect(reinterpret_cast<LPVOID>(source_function), saved_instructions_size, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;

	// patch
	CopyMemory(reinterpret_cast<LPVOID>(source_function), patch, saved_instructions_size);

	// enable memory protection
	VirtualProtect(reinterpret_cast<LPVOID>(source_function), saved_instructions_size, oldProtect, &oldProtect);
	
	return true;
}

/**************************************************************************************************
 * Removes the hook.
 *
 * @author marpie
 * @date 2011-10-26
 *
 * @return true if it succeeds, false if it fails.
 **************************************************************************************************/

bool HookTraditional::RemoveHook(void)
{
	if (!saved_instructions)
		return false;

	HeapFree(hHeap, 0, patch);

	// enable write access to the location to patch
	DWORD oldProtect = 0;
	if (!VirtualProtect(reinterpret_cast<LPVOID>(source_function), saved_instructions_size, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;

	// remove patch
	CopyMemory(reinterpret_cast<LPVOID>(source_function), saved_instructions, saved_instructions_size);

	// enable memory protection
	VirtualProtect(reinterpret_cast<LPVOID>(source_function), saved_instructions_size, oldProtect, &oldProtect);

	freeSaveInstructions();

	return true;
}
