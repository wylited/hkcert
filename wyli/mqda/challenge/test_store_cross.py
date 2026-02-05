#!/usr/bin/env python3
"""
Test STORE cross-page write.

When address low byte > 0xFC, STORE enters cross-page mode:
- r14 = (addr_low - 0xFC) = bytes for second page
- First write: page1[addr_low + 4]
- Then some bytes go to page2[4...] 

For addr_low = 0xFD: r14 = 1, 3 bytes in page1, 1 byte in page2
For addr_low = 0xFE: r14 = 2, 2 bytes in page1, 2 bytes in page2
For addr_low = 0xFF: r14 = 3, 1 byte in page1, 3 bytes in page2

The first write is at page1[addr_low + 4]:
- 0xFD: page1[0x101]
- 0xFE: page1[0x102]
- 0xFF: page1[0x103]

All within usable. But what about the SECOND page writes?
They start at page2[4], page2[5], page2[6] - all safe.

What if we could confuse the paging system?
"""
from pwn import *

# Actually let me look at this from a different angle.
# What if the vulnerability is in how pages are freed?

# The cleanup at 0x15d0 (free_pages) iterates and frees pages.
# If page data is all zeros, page is freed and slot in page array is nulled.

# After execution ends, ALL pages get freed via another cleanup path.
# Let's see if we can cause a double-free or use-after-free.

# Can we:
# 1. Write zeros to a page to trigger mid-execution cleanup
# 2. Access the same page again (use-after-free)

# If cleanup frees page for address A, but we then access A again,
# a new page would be allocated but maybe overlapping?

print("[*] Need to investigate mid-execution cleanup")
