/**************************************************************************************************
 * @file libhook.h
 *
 * Declares the classes and patch instructions for both x86 and x86-64.
 **************************************************************************************************/

#ifndef LIBHOOK_H
#define LIBHOOK_H

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define NOP_CODE 0x90
#if defined(_X86_)	// Defined on the command line by a linker variable.
    // the target architecture is x86
	const char JUMP_PATCH[] =	"\xc7\xc0\xdd\xcc\xbb\xaa"	// mov eax, AABBCCDDh
								"\xff\xe0";					// jmp far [eax]
	#define JUMP_LOCATION 2
	#define JUMP_PATCH_SIZE 8
#elif defined(_AMD64_)
    // the target architecture is AMD x86-64
	const char JUMP_PATCH[] =	"\x48\xb8\xEF\xCD\xAB\x90\x78\x56\x34\x12"	// mov rax, 1234567890ABCDEFh
								"\xff\xe0";									// jmp far [rax]
	#define JUMP_LOCATION 2
	#define JUMP_PATCH_SIZE 12
#endif

/**************************************************************************************************
 * The Hook base class is used for all other hooks. It implements functions to disassemble a
 * given function pointer and returns the instructions of a given size, etc.
 *
 * @author marpie
 * @date 2011-10-21
 **************************************************************************************************/

class Hook
{
protected:
	HANDLE hHeap;
	LPVOID source_function;
	LPVOID destination_function;
	int saved_instructions_size;
	char *saved_instructions;

	int getCompleteInstructions(const int size_needed, char *out_buffer, int *out_size);
	bool saveInstructions(const int size_needed);
	void freeSaveInstructions(void);

public:
	Hook(LPVOID src_func, LPVOID dest_func);
	~Hook();

	bool ApplyHook(void) { ; };
	bool RemoveHook(void) { ; };

	const char *getSavedInstructionsPtr(void) { return static_cast<const char *>(saved_instructions); };
	const int getSavedInstructionsSize(void) { return static_cast<const int>(saved_instructions_size); };
};

/**************************************************************************************************
 * Implements a traditional hook. It places a jmp to the hooking function at the first bytes of
 * the original function and replaces that code on every invokation. It's a rather slow and
 * error-prone implementation.
 *
 * @author marpie
 * @date 2011-10-21
 **************************************************************************************************/

class HookTraditional: public Hook
{
private:
	char *patch;

public:
	HookTraditional(LPVOID src_func, LPVOID dest_func): Hook(src_func, dest_func)
	{
		patch = nullptr;
	};

	bool ApplyHook(void);
	bool RemoveHook(void);
};

/**************************************************************************************************
 * Detour Hooking Class
 *
 * @author marpie
 * @date 2011-10-26
 **************************************************************************************************/

class HookDetour: public Hook
{
private:
	LPVOID trampoline_function;
public:
	HookDetour(LPVOID src_func, LPVOID dest_func): Hook(src_func, dest_func)
	{
		trampoline_function = nullptr;
	};

	bool ApplyHook(void);
	bool RemoveHook(void);
};

#endif
