/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "adt.h"
#include "aic.h"
#include "aic_regs.h"
#include "hv.h"
#include "uartproxy.h"
#include "utils.h"

#define IRQTRACE_IRQ BIT(0)

static u32 trace_hw_num[AIC_MAX_DIES][AIC_MAX_HW_NUM / 32];

static bool trace_aic_valid(void)
{
    return aic && aic->max_irq && aic->max_irq <= AIC_MAX_HW_NUM && aic->nr_die &&
           aic->nr_die <= AIC_MAX_DIES && aic->nr_irq <= aic->max_irq;
}

static void emit_irqtrace(u16 die, u16 type, u16 num)
{
    struct hv_evt_irqtrace evt = {
        .flags = IRQTRACE_IRQ,
        .type = type,
        .num = die * aic->max_irq + num,
    };

    hv_wdt_suspend();
    uartproxy_send_event(EVT_IRQTRACE, &evt, sizeof(evt));
    hv_wdt_resume();
}

static bool trace_aic_event(struct exc_info *ctx, u64 addr, u64 *val, bool write, int width)
{
    if (!trace_aic_valid())
        return false;

    if (!hv_pa_rw(ctx, addr, val, write, width))
        return false;

    if (addr != (aic->base + aic->regs.event) || write || width != 2) {
        return true;
    }

    u16 die = FIELD_GET(AIC_EVENT_DIE, *val);
    u16 type = FIELD_GET(AIC_EVENT_TYPE, *val);
    u16 num = FIELD_GET(AIC_EVENT_NUM, *val);

    if (die >= AIC_MAX_DIES || die >= aic->nr_die || num >= AIC_MAX_HW_NUM ||
        num >= aic->nr_irq)
        return true;

    switch (type) {
        case AIC_EVENT_TYPE_HW:
            if (trace_hw_num[die][num / 32] & BIT(num & 31)) {
                emit_irqtrace(die, type, num);
            }
            break;
        default:
            // ignore
            break;
    }

    return true;
}

bool hv_trace_irq(u32 type, u32 num, u32 count, u32 flags)
{
    dprintf("HV: hv_trace_irq type: %u start: %u num: %u flags: 0x%x\n", type, num, count, flags);
    if (type != AIC_EVENT_TYPE_HW) {
        printf("HV: not handling AIC event type: 0x%02x num: %u\n", type, num);
        return false;
    }
    if (!trace_aic_valid()) {
        printf("HV: AIC not initialized or invalid\n");
        return false;
    }

    u32 die = num / aic->max_irq;
    num %= aic->max_irq;
    if (die >= aic->nr_die || num >= aic->nr_irq || count > aic->nr_irq - num) {
        printf("HV: invalid IRQ range: start %u count %u for die %u\n", num, count, die);
        return false;
    }

    static bool hooked = false;
    if (!hooked) {
        if (hv_map_hook(aic->base, trace_aic_event, aic->regs.reg_size) < 0)
            return false;
        hooked = true;
    }

    for (u32 n = num; n < num + count; n++) {
        switch (flags) {
            case IRQTRACE_IRQ:
                trace_hw_num[die][n / 32] |= BIT(n & 31);
                break;
            default:
                trace_hw_num[die][n / 32] &= ~(BIT(n & 31));
                break;
        }
    }

    return true;
}
