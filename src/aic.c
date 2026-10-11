/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "aic.h"
#include "adt.h"
#include "aic_regs.h"
#include "assert.h"
#include <string.h>
#include "utils.h"

#define MASK_REG(x) (4 * ((x) >> 5))
#define MASK_BIT(x) BIT((x) & GENMASK(4, 0))

static struct aic aic1 = {
    .version = 1,
    .nr_die = 1,
    .max_die = 1,
    .regs =
        {
            .reg_size = AIC_REG_SIZE,
            .event = AIC_EVENT,
            .tgt_cpu = AIC_TARGET_CPU,
            .sw_set = AIC_SW_SET,
            .sw_clr = AIC_SW_CLR,
            .mask_set = AIC_MASK_SET,
            .mask_clr = AIC_MASK_CLR,
        },
};

static struct aic aic2 = {
    .version = 2,
    .regs =
        {
            .config = AIC2_IRQ_CFG,
        },
    .cap0_offset = AIC2_CAP0,
    .maxnumirq_offset = AIC2_MAXNUMIRQ,
};

static struct aic aic3 = {
    .version = 3,
    /* These are dynamic on AIC3, and filled in from the DT */
    .cap0_offset = -1,
    .maxnumirq_offset = -1,
};

struct aic *aic;

/* Declared ADT register aperture, separate from the HV event-hook size. */
static u64 aic_aperture;

static bool aic_range(u64 offset, u64 size)
{
    return aic && !(offset & 3) && offset <= aic_aperture &&
           size <= aic_aperture - offset;
}

static bool aic_bank_range(u64 offset, u32 stride, u64 size)
{
    if ((stride & 3) || (aic->nr_die > 1 && stride < size))
        return false;
    return aic_range(offset + (u64)(aic->nr_die - 1) * stride, size);
}

static int aic_getprop_exact(int node, const char *name, void *out, size_t len)
{
    u32 actual_len = 0;
    const void *raw = adt_getprop(adt, node, name, &actual_len);
    if (!raw || actual_len != len)
        return -1;
    memcpy(out, raw, len);
    return 1;
}

static int aic23_init(int version, int node)
{
    int ret = aic_getprop_exact(node, "aic-iack-offset", &aic->regs.event,
                                sizeof(aic->regs.event));
    if (ret < 0) {
        printf("AIC: failed to get property aic-iack-offset\n");
        return ret;
    }

    int32_t cap0_offset = aic->cap0_offset;
    if (cap0_offset == -1) {
        ret = aic_getprop_exact(node, "cap0-offset", &cap0_offset, sizeof(cap0_offset));
        if (ret < 0) {
            printf("AIC: failed to get property cap0-offset\n");
            return ret;
        }
    }

    int32_t maxnumirq_offset = aic->maxnumirq_offset;
    if (maxnumirq_offset == -1) {
        ret = aic_getprop_exact(node, "maxnumirq-offset", &maxnumirq_offset,
                                sizeof(maxnumirq_offset));
        if (ret < 0) {
            printf("AIC: failed to get property maxnumirq-offset\n");
            return ret;
        }
    }

    if (cap0_offset < 0 || cap0_offset % 4 || maxnumirq_offset < 0 || maxnumirq_offset % 4) {
        printf("AIC: invalid capability register offset\n");
        return -1;
    }

    /* Validate both capability reads and IACK before the first MMIO access. */
    if (!aic_range(cap0_offset, sizeof(u32)) ||
        !aic_range(maxnumirq_offset, sizeof(u32)) ||
        !aic_range(aic->regs.event, sizeof(u32))) {
        printf("AIC: capability or event register outside aperture\n");
        return -1;
    }

    u32 cap0 = read32(aic->base + cap0_offset);
    aic->nr_die = FIELD_GET(AIC23_CAP0_LAST_DIE, cap0) + 1;
    aic->nr_irq = FIELD_GET(AIC23_CAP0_NR_IRQ, cap0);

    u32 info3 = read32(aic->base + maxnumirq_offset);
    aic->max_die = FIELD_GET(AIC23_MAXNUMIRQ_MAX_DIE, info3);
    aic->max_irq = FIELD_GET(AIC23_MAXNUMIRQ_MAX_IRQ, info3);

    if (aic->nr_die > AIC_MAX_DIES) {
        printf("AIC: more dies than supported: %u\n", aic->max_die);
        return -1;
    }

    /* Preserve the existing word-sized bank layout; do not invent a partial-bank layout. */
    if (!aic->max_irq || aic->max_irq > AIC_MAX_HW_NUM || (aic->max_irq & 31) ||
        aic->nr_irq > aic->max_irq) {
        printf("AIC: unsupported IRQ capacity: %u/%u\n", aic->nr_irq, aic->max_irq);
        return -1;
    }

    /*
     * This is dynamic on AIC3+, and already filled in on the AIC2 so the call failing is fine on
     * AIC2, but fatal on AIC3.
     */
    aic->regs.config = version == 2 ? AIC2_IRQ_CFG : 0;
    u32 config_base;
    if (aic_getprop_exact(node, "extint-baseaddress", &config_base, sizeof(config_base)) > 0) {
        aic->regs.config = config_base;
    }

    if (!aic->regs.config) {
        printf("AIC: Could not find external interrupt config base\n");
        return -1;
    }

    const u64 start_off = aic->regs.config;
    u64 off = start_off + sizeof(u32) * aic->max_irq; /* IRQ_CFG */
    aic->regs.sw_set = off;
    off += sizeof(u32) * (aic->max_irq >> 5); /* SW_SET */
    aic->regs.sw_clr = off;
    off += sizeof(u32) * (aic->max_irq >> 5); /* SW_CLR */
    aic->regs.mask_set = off;
    off += sizeof(u32) * (aic->max_irq >> 5); /* MASK_SET */
    aic->regs.mask_clr = off;
    off += sizeof(u32) * (aic->max_irq >> 5); /* MASK_CLR */
    off += sizeof(u32) * (aic->max_irq >> 5); /* HW_STATE */

    /* Fill in the strides dynamically if we can */
    if (aic_getprop_exact(node, "extintrcfg-stride", &aic->extintrcfg_stride,
                         sizeof(aic->extintrcfg_stride)) < 0)
        aic->extintrcfg_stride = off - start_off;
    if (aic_getprop_exact(node, "intmaskset-stride", &aic->intmaskset_stride,
                         sizeof(aic->intmaskset_stride)) < 0)
        aic->intmaskset_stride = off - start_off;
    if (aic_getprop_exact(node, "intmaskclear-stride", &aic->intmaskclear_stride,
                         sizeof(aic->intmaskclear_stride)) < 0)
        aic->intmaskclear_stride = off - start_off;

    const u64 cfg_size = sizeof(u32) * aic->max_irq;
    const u64 mask_size = sizeof(u32) * (aic->max_irq >> 5);
    if (!aic_range(start_off, off - start_off) ||
        !aic_bank_range(aic->regs.config, aic->extintrcfg_stride, cfg_size) ||
        !aic_bank_range(aic->regs.sw_set, aic->intmaskset_stride, mask_size) ||
        !aic_bank_range(aic->regs.sw_clr, aic->intmaskclear_stride, mask_size) ||
        !aic_bank_range(aic->regs.mask_set, aic->intmaskset_stride, mask_size) ||
        !aic_bank_range(aic->regs.mask_clr, aic->intmaskclear_stride, mask_size)) {
        printf("AIC: invalid register bank or die stride\n");
        return -1;
    }

    /* Keep the event-hook extent, not the full declared MMIO aperture. */
    aic->regs.reg_size = aic->regs.event + 4;

    printf("AIC: AIC%d with %u/%u dies, %u/%u IRQs, reg_size:%05lx, config:%05lx, "
           "extintrcfg_stride:%05x, intmaskset_stride:%05x, intmaskclear_stride:%05x\n",
           version, aic->nr_die, aic->max_die, aic->nr_irq, aic->max_irq, aic->regs.reg_size,
           aic->regs.config, aic->extintrcfg_stride, aic->intmaskset_stride,
           aic->intmaskclear_stride);

    u32 ext_intr_config_len;
    const u8 *ext_intr_config = adt_getprop(adt, node, "aic-ext-intr-cfg", &ext_intr_config_len);

    if (ext_intr_config) {
        if (ext_intr_config_len % 3) {
            printf("AIC: malformed external interrupt configuration\n");
            return -1;
        }

        printf("AIC: Configuring %d external interrupts\n", ext_intr_config_len / 3);
        for (u32 i = 0; i < ext_intr_config_len; i += 3) {
            u8 die = ext_intr_config[i + 1] >> 4;
            u16 irq = ext_intr_config[i] | ((ext_intr_config[i + 1] & 0xf) << 8);
            if (die >= aic->nr_die || irq >= aic->nr_irq) {
                printf("AIC: external interrupt configuration out of range\n");
                return -1;
            }
        }
        for (u32 i = 0; i < ext_intr_config_len; i += 3) {
            u8 die = ext_intr_config[i + 1] >> 4;
            u16 irq = ext_intr_config[i] | ((ext_intr_config[i + 1] & 0xf) << 8);
            u8 target = ext_intr_config[i + 2];
            mask32(aic->base + aic->regs.config + (u64)die * aic->extintrcfg_stride + 4 * irq,
                   AIC23_IRQ_CFG_TARGET, FIELD_PREP(AIC23_IRQ_CFG_TARGET, target));
        }
    }

    return 0;
}

void aic_init(void)
{
    aic = NULL;
    aic_aperture = 0;
    int path[8];
    int node = adt_path_offset_trace(adt, "/arm-io/aic", path);

    if (node < 0) {
        printf("AIC node not found!\n");
        return;
    }

    if (adt_is_compatible(adt, node, "aic,1")) {
        aic = &aic1;
    } else if (adt_is_compatible(adt, node, "aic,2")) {
        aic = &aic2;
    } else if (adt_is_compatible(adt, node, "aic,3")) {
        aic = &aic3;
    } else {
        printf("AIC: Error: Unsupported version\n");
        return;
    }

    if (adt_get_reg(adt, path, "reg", 0, &aic->base, &aic_aperture)) {
        printf("Failed to get AIC reg property!\n");
        aic = NULL;
        return;
    }
    if (!aic->base || (aic->base & 3) || !aic_aperture ||
        aic_aperture > UINT64_MAX - aic->base) {
        printf("AIC: invalid register aperture\n");
        aic = NULL;
        return;
    }

    if (aic->version == 1) {
        if (!aic_range(0, AIC_REG_SIZE)) {
            printf("AIC: incomplete fixed register aperture\n");
            aic = NULL;
            return;
        }
        printf("AIC: Version 1 @ 0x%lx\n", aic->base);
        aic->nr_irq = FIELD_GET(AIC_INFO_NR_HW, read32(aic->base + AIC_INFO));
        aic->max_irq = AIC1_MAX_IRQ;
        if (aic->nr_irq > aic->max_irq) {
            printf("AIC: IRQ count exceeds fixed capacity\n");
            aic = NULL;
        }
    } else if (aic->version == 2) {
        printf("AIC: Version 2 @ 0x%lx\n", aic->base);
        int ret = aic23_init(2, node);
        if (ret < 0)
            aic = NULL;
    } else if (aic->version == 3) {
        printf("AIC: Version 3 @ 0x%lx\n", aic->base);
        int ret = aic23_init(3, node);
        if (ret < 0)
            aic = NULL;
    }
}

void aic_set_sw(int irq, bool active)
{
    if (!aic || irq < 0 || !aic->max_irq)
        return;
    u32 die = (u32)irq / aic->max_irq;
    u32 local = (u32)irq % aic->max_irq;
    if (die >= aic->nr_die || local >= aic->nr_irq)
        return;
    u64 offset = active ? aic->regs.sw_set : aic->regs.sw_clr;
    u32 stride = active ? aic->intmaskset_stride : aic->intmaskclear_stride;
    offset += (u64)die * stride + MASK_REG(local);
    if (aic_range(offset, sizeof(u32)))
        write32(aic->base + offset, MASK_BIT(local));
}

void aic_write(u32 reg, u32 val)
{
    if (aic_range(reg, sizeof(u32)))
        write32(aic->base + reg, val);
}

uint32_t aic_ack(void)
{
    if (!aic || !aic_range(aic->regs.event, sizeof(u32)))
        return 0;
    return read32(aic->base + aic->regs.event);
}
