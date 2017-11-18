/**
 * Bareflank EL2 boot stub: exception handler
 * Handles all exceptions, including a return to EL2.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <k@ktemkin.com>
 *
 * <insert license here>
 */

#include <stdint.h>
#include <microlib.h>

#include "image.h"
#include "exceptions.h"

/**
 * Simple debug function that prints all of our saved registers.
 */
static void print_registers(struct el1_registers *regs)
{
    // print x0-29
    for(int i = 0; i < 30; i += 2) {
        printf("x%d:\t0x%p\t", i,     regs->x[i]);
        printf("x%d:\t0x%p\n", i + 1, regs->x[i + 1]);
    }

    // print x30; don't bother with x31 (SP), as it's used by the stack that's
    // storing this stuff; we really care about the saved SP anyways
    printf("x30:\t0x%p\n", regs->x[30]);

    // Special registers.
    printf("pc:\t0x%p\tcpsr:\t0x%p\n", regs->pc, regs->cpsr);
    printf("sp_el1:\t0x%p\tsp_el0:\t0x%p\n", regs->sp_el1, regs->sp_el0);
    printf("elr_el1:0x%p\tspsr_el1:0x%p\n", regs->elr_el1, regs->spsr_el1);

    // Note that we don't print ESR_EL2, as this isn't really part of the saved state.
}

/**
 * Placeholder function that triggers whenever a vector happens we're not
 * expecting. Currently prints out some debug information.
 */
void unhandled_vector(struct el1_registers *regs)
{
    printf("\nAn unexpected vector happened!\n");
    print_registers(regs);
    printf("\n\n");
}

/**
 * Placeholder function that triggers whenever a user event triggers a
 * synchronous interrupt. Currently, we really only care about 'hvc',
 * so that's all we're going to handle here.
 */

void handle_hypercall(struct el1_registers *regs)
{
    // This is demonstration code.
    // In the future, you'd stick your hypercall table here for the minimial
    // amount of hypercalls you'd use to 

    switch (regs->esr_el2.ec) {

    case HSR_EC_HVC64: {
        // Read the hypercall number.
        int hvc_nr = regs->esr_el2.iss & 0xFFFF;

        printf("Got a HVC call from 64-bit code.\n");
        printf("Calling instruction was: hvc %d\n\n", hvc_nr);
        printf("Calling context (you can use these regs as hypercall args!):\n");
        print_registers(regs);
        printf("\n\n");
        break;
    }
    default:
        printf("Unexpected hypercall! ESR=%p\n", regs->esr_el2.bits);
        print_registers(regs);
        printf("\n\n");
        break;

    }
}


