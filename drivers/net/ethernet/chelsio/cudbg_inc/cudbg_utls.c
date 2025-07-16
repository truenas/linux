#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
#if defined(_MSC_VER) || defined(__GNUC__)
#pragma warning(disable : 4244)
#endif
#endif
#include <cudbg_lib_common.h>
static int mem_desc_cmp(const void *a, const void *b);
static void u32_swap(void *a, void *b, int size);
static void generic_swap(void *a1, void *b1, int size);

static int mem_desc_cmp(const void *a, const void *b)
{
	return ((const struct struct_mem_desc *)a)->base -
		((const struct struct_mem_desc *)b)->base;
}

static void u32_swap(void *a, void *b, int size)
{
	u32 t = *(u32 *)a;

	*(u32 *)a = *(u32 *)b;
	*(u32 *)b = t;
}

static void generic_swap(void *a1, void *b1, int size)
{
	u8 t;
	u8 *a = (u8 *)a1;
	u8 *b = (u8 *)b1;

	do {
		t = *a;
		*(a++) = *b;
		*(b++) = t;
	} while (--size > 0);
}

/**
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap_func function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */
void sort_t(void *base_val, int num, int size,
	    int (*cmp_func)(const void *, const void *),
	    void (*swap_func)(void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num / 2 - 1) * size;
	int n = num * size;
	int c, r;
	u8 *base = (u8 *)base_val;

	if (!swap_func)
		swap_func = (size == 4 ? u32_swap : generic_swap);

	/* heapify */
	for (; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r  = c) {
			c = r * 2 + size;
			if (c < n - size &&
			    cmp_func(base + c, base + c + size) < 0)
				c += size;
			if (cmp_func(base + r, base + c) >= 0)
				break;
			swap_func(base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size) {
		swap_func(base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size &&
			    cmp_func(base + c, base + c + size) < 0)
				c += size;
			if (cmp_func(base + r, base + c) >= 0)
				break;
			swap_func(base + r, base + c, size);
		}
	}
}

static inline uint8_t count_set_bits(uint32_t word32)
{
	uint8_t count = 0;

	while (word32) {
		count += word32 & 1;
		word32 >>= 1;
	}
	return count;
}

/* Code to read VPD data */
#define PCIE_BAR0_LENGTH	0x513FF
#define S_ENABLE		30
#define V_ENABLE(x)		((x) << S_ENABLE)
#define F_ENABLE		V_ENABLE(1U)
#define S_WRITE_BYTES		24
#define V_WRITE_BYTES(x)	((x) << S_WRITE_BYTES)
#define F_WRITE_BYTES		V_WRITE_BYTES(0xf)
#define VPD_CAP			0xD0
#define VPD_DATA		0xD4
#define SEEPROM_SIZE		0x8000

static unsigned int remap_se_addr(unsigned int addr)
{
	if (addr >= 0x400)
		return addr - 0x400;
	return 0x7C00 + addr;
}

static unsigned int read_pci(struct adapter *padap, unsigned addr)
{
	u32 req_mask = 0;

	if (is_t5(padap->params.chip))
		req_mask = F_ENABLE | F_WRITE_BYTES;
	else
		req_mask = F_T6_ENABLE | V_T6_WRBE(0xFU);

	t4_write_reg(padap, A_PCIE_CFG_SPACE_REQ, addr | req_mask);
	return t4_read_reg(padap, A_PCIE_CFG_SPACE_DATA);
}

static unsigned wait_vpd_cap_not_busy(struct adapter *padap,
				      unsigned busy_polarity, int timeout)
{
	unsigned busy = 1;
	unsigned cnt = 0;

	while (busy) {
		unsigned raw_busy = read_pci(padap, VPD_CAP);

		cnt++;
		busy = (busy_polarity == ((raw_busy >> 31) & 1));
	}
	return busy;
}

static void write_pci(struct adapter *padap, unsigned addr, unsigned data)
{
	u32 req_mask = 0;

	if (is_t5(padap->params.chip))
		req_mask = F_ENABLE | F_WRITE_BYTES;
	else
		req_mask = F_T6_ENABLE | V_T6_WRBE(0xFU);

	t4_write_reg(padap, A_PCIE_CFG_SPACE_REQ, addr | req_mask);
	t4_write_reg(padap, A_PCIE_CFG_SPACE_DATA, data);
}

static unsigned int se_read(struct adapter *padap, unsigned int addr)
{
	write_pci(padap, VPD_CAP, remap_se_addr(addr) << 16);
	wait_vpd_cap_not_busy(padap, 0, 0);
	return read_pci(padap, VPD_DATA);
}

static int read_vpd_reg(struct adapter *padap, int addr, int length,
			u8 *read_out)
{
	int i;
	int j = 0;
	int data;

	/* buffer to store data we read from VPD.*/
	/* With extra buffer since se_read reads dword aligned.*/
	u8 vpd_data[MAX_VPD_DATA_LEN];
	int addr_diff;
	int base_addr = addr & ~3;

	/* Read next dword b/c if we read addr 0x2 for 4 bytes, we need to
	 * read both addr 0x0 and addr 0x4.
	 */
	int max_addr;

	/* checking (addr + length) is multiple of 4 or not */
	if (((addr + length) & 3) == 0)
		max_addr = addr + length;
	else
		max_addr = ((addr + length) & ~3) + 4;

	/* Read from VPD and put each character into the buffer.
	 * se_read() returns value that is byte swapped so we mask MSB starting
	 * from right.
	 */
	for (i = base_addr; i < max_addr; i += 4) {
		data = se_read(padap, i);
		vpd_data[j++] = (data & 0x000000ff);
		vpd_data[j++] = (data & 0x0000ff00) >> 8;
		vpd_data[j++] = (data & 0x00ff0000) >> 16;
		vpd_data[j++] = (data & 0xff000000) >> 24;
	}
	vpd_data[j] = '\0';  /* end string*/

	/* Need to figure out where in our buffer to start printing our string
	 * because se_read() reads from dword aligned addresses. For example,
	 * reading 0xae2 will return the whole dword from 0xae0-0xae3.
	 */
	addr_diff = addr - base_addr;
	for (i = addr_diff, j = 0; i < (addr_diff + length); i++)
		read_out[j++] = vpd_data[i];

	read_out[j] = '\0';

	return 0;
}

static inline unsigned int cudbg_round_up(unsigned int x, unsigned int y)
{
	return ((x + y - 1) / y) * y;
}

static inline unsigned int cudbg_round_down(unsigned int x, unsigned int y)
{
	return (x / y) * y;
}
