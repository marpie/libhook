/**************************************************************************************************
 * @file hook_detour.cpp
 *
 * Implements the detour hooking class.
 **************************************************************************************************/

#include "libhook.h"

bool HookDetour::ApplyHook(void)
{
/*
	- save the instructions
												 jmp to hook function						 jmp to (original function + saved_instructions_size)
	- allocate space for the trampoline function JUMP_PATCH_SIZE      + saved_instructions + JUMP_PATCH_SIZE
	- prepare trampoline function
	- patch the original function
*/
	return true;
}

bool HookDetour::RemoveHook(void)
{
	return true;
}
