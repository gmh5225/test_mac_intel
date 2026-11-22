/* Read the Windows PE inbox Null driver's two documented arguments at its
   original PE entry. The probe reports object identities and the counted name. */
#include <glib.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "fixture.h"
#include "layout.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static struct qemu_plugin_register *x0, *x1;
static GByteArray *scratch;
static gboolean published;

static void registers(qemu_plugin_id_t id, unsigned int cpu) {
    (void)id;
    if (cpu != 0)
        return;
    GArray *rows = qemu_plugin_get_registers();
    for (guint i = 0; i < rows->len; ++i) {
        qemu_plugin_reg_descriptor r = g_array_index(rows, qemu_plugin_reg_descriptor, i);
        if (strcmp(r.name, "x0") == 0)
            x0 = r.handle;
        if (strcmp(r.name, "x1") == 0)
            x1 = r.handle;
    }
    g_array_free(rows, TRUE);
}

static gboolean read_field(uint64_t address, void *output, size_t size) {
    g_byte_array_set_size(scratch, 0);
    if (!qemu_plugin_read_memory_vaddr(address, scratch, size) || scratch->len != size)
        return FALSE;
    memcpy(output, scratch->data, size);
    return TRUE;
}

static gboolean read_arg(struct qemu_plugin_register *reg, uint64_t *value) {
    g_byte_array_set_size(scratch, 0);
    if (!reg || qemu_plugin_read_register(reg, scratch) != sizeof(*value) ||
        scratch->len != sizeof(*value))
        return FALSE;
    memcpy(value, scratch->data, sizeof(*value));
    return TRUE;
}

static void observe(unsigned int cpu, void *data) {
    uint64_t pc = (uintptr_t)data, base = pc - ENTRY_RVA, object, string, owner, buffer;
    uint32_t image_size, timestamp, actual_entry;
    uint16_t type, length, maximum, machine;
    unsigned char prefix[sizeof(entry_bytes)];
    if (cpu || published || !read_field(pc, prefix, sizeof(prefix)) ||
        memcmp(prefix, entry_bytes, sizeof(prefix)) ||
        !read_field(base + PE_OFFSET + 4, &machine, 2) || machine != 0xaa64 ||
        !read_field(base + PE_OFFSET + 8, &timestamp, 4) || timestamp != PE_TIME ||
        !read_field(base + PE_OFFSET + 40, &actual_entry, 4) || actual_entry != ENTRY_RVA ||
        !read_field(base + PE_OFFSET + 80, &image_size, 4) || image_size != IMAGE_SIZE)
        return;
    if (!read_arg(x0, &object) || !read_arg(x1, &string) || !(object >> 63) ||
        !(string >> 63) || object == string || (object & 7) || (string & 7) ||
        !read_field(object, &type, 2) || type != DRIVER_TYPE ||
        !read_field(object + DRIVER_START_OFFSET, &owner, 8) || owner != base ||
        !read_field(string, &length, 2) || !read_field(string+2, &maximum, 2) ||
        !length || length > maximum || (length & 1) || length > 512 ||
        !read_field(string + UNICODE_BUFFER_OFFSET, &buffer, 8) || !(buffer >> 63))
        return;
    uint16_t path[256];
    if (!read_field(buffer, path, length))
        return;
    GError *error = NULL;
    gchar *name = g_utf16_to_utf8(path, length / 2, NULL, NULL, &error);
    if (!name) {
        g_clear_error(&error);
        return;
    }
    gchar *lower = g_ascii_strdown(name, -1);
    gboolean matched = g_str_has_prefix(lower, "\\registry\\machine\\system\\") &&
                       g_str_has_suffix(lower, "\\services\\null");
    g_free(lower);
    if (matched) {
        gchar *escaped = g_strescape(name, NULL);
        char *report = g_strdup_printf("{\"guest\":\"Microsoft Windows PE ARM64\","
            "\"driver\":\"null.sys\",\"event\":\"original PE entry before its first instruction\","
            "\"entry_rva\":%u,\"driver_object_type\":%u,\"x0_driver_start_matches_image\":true,"
            "\"x1_counted_registry_path\":\"%s\",\"registry_length_bytes\":%u,"
            "\"both_arguments_distinct_and_aligned\":true}\n", ENTRY_RVA, type, escaped, length);
        if (g_file_set_contents("observed.json", report, -1, &error))
            published = TRUE;
        else {
            g_printerr("Could not record the observed entry: %s\n", error->message);
            g_clear_error(&error);
        }
        g_free(report);
        g_free(escaped);
    }
    g_free(name);
}

static void translated(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    if (published || !(pc >> 63) || (pc & 4095) != (ENTRY_RVA & 4095) ||
        !qemu_plugin_tb_n_insns(tb))
        return;
    struct qemu_plugin_insn *first = qemu_plugin_tb_get_insn(tb, 0);
    unsigned char op[4];
    if (qemu_plugin_insn_data(first, op, sizeof(op)) == sizeof(op) &&
        memcmp(op, entry_bytes, sizeof(op)) == 0)
        qemu_plugin_register_vcpu_insn_exec_cb(first, observe, QEMU_PLUGIN_CB_R_REGS,
                                              (void *)(uintptr_t)pc);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                            int argc, char **argv) {
    (void)argv;
    if (argc || !info->system_emulation || strcmp(info->target_name, "aarch64") ||
        info->system.smp_vcpus != 1 || G_BYTE_ORDER != G_LITTLE_ENDIAN)
        return 1;
    scratch = g_byte_array_new();
    qemu_plugin_register_vcpu_init_cb(id, registers);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translated);
    return 0;
}
