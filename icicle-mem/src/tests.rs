use crate::{perm, AllocLayout, Mapping, MemError, Mmu, Resettable};

#[cfg(not(miri))]
const ITERATIONS: u64 = 1000;

#[cfg(miri)]
const ITERATIONS: u64 = 1;

macro_rules! assert_unmapped {
    ($mmu:expr, $addr:expr) => {{
        match $mmu.read::<1>($addr, perm::NONE) {
            Err(MemError::Unmapped) => {}
            _ => panic!("expected: {:#0x} to be unmapped:\n{:#0x?}", $addr, $mmu.get_mapping()),
        }
        match $mmu.write($addr, [0], perm::NONE) {
            Err(MemError::Unmapped) => {}
            _ => panic!("expected: {:#0x} to be unmapped:\n{:#0x?}", $addr, $mmu.get_mapping()),
        }
    }};
}

#[test]
fn write_pages() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x0, 0x1000 * ITERATIONS, Mapping { perm: perm::NONE, value: 0xAA });
    eprintln!("{:#0x?}", mmu.get_mapping());

    for i in 0..ITERATIONS {
        let payload = [0x12; 0x100];
        mmu.write_bytes(0x1000 * i, &payload, perm::NONE).unwrap();

        let mut output = [0x00; 0x100];
        mmu.read_bytes(0x1000 * i, &mut output, perm::INIT).unwrap();

        assert_eq!(&output[..], &payload[..])
    }
}

#[test]
fn write_across_boundary() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x20000, 0x2000, Mapping { perm: perm::NONE, value: 0xAA });

    let payload = [0xFE; 0xFFC];
    mmu.write_bytes(0x20170, &payload, perm::NONE).unwrap();

    let mut output = [0x00; 0xFFC];
    mmu.read_bytes(0x20170, &mut output, perm::INIT).unwrap();

    assert_eq!(&output[..], &payload[..])
}

#[test]
fn memset() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x10000, 0x2000, Mapping { perm: perm::NONE, value: 0xAA });

    mmu.fill_mem(0x10500, 0x1000, 0x10).unwrap();

    eprintln!("{:#0x?}", mmu.get_mapping());

    let mut output = [0x0; 1];
    mmu.read_bytes(0x10500 - 1, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0xAA);

    mmu.read_bytes(0x10500 + 0x1000, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0xAA);

    eprintln!("{:#0x?}", mmu.get_mapping());

    mmu.read_bytes(0x10500, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0x10);

    mmu.read_bytes(0x11000, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0x10);
}

#[test]
fn memset_middle_of_mapped_memory() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x10000, 0x3000, Mapping { perm: perm::NONE, value: 0xAA });

    mmu.fill_mem(0x11000, 0x1000, 0x10).unwrap();

    // Check that before the set the value is correct
    let mut output = [0x0; 1];
    mmu.read_bytes(0x11000 - 1, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0xAA);

    // Check that after the set the value is correct
    mmu.read_bytes(0x11000 + 0x1000, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0xAA);

    // Check that inside of the set is correct
    mmu.read_bytes(0x11000, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0x10);

    mmu.read_bytes(0x12000 - 1, &mut output, perm::NONE).unwrap();
    assert_eq!(output[0], 0x10);
}

#[test]
fn permission_checks() {
    let mut mmu = Mmu::new();

    let payload = [0xFE; 0x100];
    let mut output = [0x00; 0x100];

    mmu.write_bytes(0x10000, &payload, perm::WRITE).unwrap_err();
    mmu.read_bytes(0x10000, &mut output, perm::READ | perm::INIT).unwrap_err();
    mmu.read_bytes(0x10000, &mut output, perm::READ | perm::INIT).unwrap_err();

    mmu.map_memory_len(0x10000, 0x1000, Mapping { perm: perm::WRITE | perm::READ, value: 0 });

    mmu.read_bytes(0x10000, &mut output, perm::READ | perm::INIT).unwrap_err(); // still uninitialized

    mmu.write_bytes(0x10000, &payload, perm::WRITE).unwrap();
    mmu.read_bytes(0x10000, &mut output, perm::INIT | perm::READ).unwrap();

    assert_eq!(&output[..], &payload[..])
}

#[test]
fn unmap() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x10000, 0x10000, Mapping { perm: perm::NONE, value: 0xAA });

    // Start of region
    mmu.unmap_memory_len(0x10000, 0x1000);
    // Middle of region
    mmu.unmap_memory_len(0x15000, 0x1000);
    // End of region
    mmu.unmap_memory_len(0x1f000, 0x1000);

    let mapping: Vec<_> = mmu.get_mapping().iter().map(|(start, end, _)| (start, end)).collect();
    assert_eq!(&mapping, &[(0x11000, 0x14fff), (0x16000, 0x1efff)]);
}

#[test]
fn map_partial() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x10000 - 0x100, 0x1000, Mapping { perm: perm::NONE, value: 0xAA });

    let mut out = [0x00; 0x3];
    mmu.read_bytes(0x10000 - 0x100, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0xaa, 0xaa, 0xaa]);

    mmu.write_bytes(0x10000 - 0x100, &[0x0, 0x1, 0x2], perm::NONE).unwrap();
    mmu.read_bytes(0x10000 - 0x100, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0x0, 0x1, 0x2]);

    assert_unmapped!(&mut mmu, 0x10000 - 0x200);

    mmu.write_bytes(0x10000, &[0x0, 0x1, 0x2], perm::NONE).unwrap();
    mmu.read_bytes(0x10000, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0x0, 0x1, 0x2]);

    assert_unmapped!(&mut mmu, 0x10000 - 0x200);
}

#[test]
fn map_partial_after_init() {
    let mut out = [0x00; 0x3];

    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x100000, 0xcf4, Mapping { perm: perm::READ | perm::WRITE, value: 0xaa });
    mmu.write_bytes(0x100000, &[0x0, 0x1, 0x2], perm::NONE).unwrap();
    mmu.read_bytes(0x100000, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0x0, 0x1, 0x2]);
    eprintln!("{:#0x?}", mmu.get_mapping());

    mmu.map_memory_len(0x100cf4, 0x2000, Mapping { perm: perm::READ | perm::WRITE, value: 0xbb });
    eprintln!("{:#0x?}", mmu.get_mapping());

    mmu.read_bytes(0x100cf4, &mut out, perm::NONE).unwrap();
    eprintln!("{:#0x?}", mmu.get_mapping());
    assert_eq!(out, [0xbb, 0xbb, 0xbb]);

    mmu.read_bytes(0x100000, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0x0, 0x1, 0x2]);
}

#[test]
fn unmap_partial() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x10000 - 0x100, 0x1000, Mapping { perm: perm::NONE, value: 0xAA });

    let mut out = [0x00; 0x3];
    mmu.read_bytes(0x10000 - 0x100, &mut out, perm::NONE).unwrap();
    assert_eq!(out, [0xaa, 0xaa, 0xaa]);

    mmu.write_bytes(0x10000 - 0x100, &[0x1, 0x2, 0x3], perm::NONE).unwrap();

    mmu.unmap_memory_len(0x10000 - 0x100, 0x1000);
    let err = mmu.read_bytes(0x10000 - 0x100, &mut out, perm::NONE).unwrap_err();
    assert_eq!(err, MemError::Unmapped);
}

#[test]
fn alloc_permissions() {
    let mut mmu = Mmu::new();
    let mapping = Mapping { perm: perm::ALL, value: 0x0 };

    let alloc1 =
        mmu.alloc_memory(AllocLayout { addr: None, size: 0x100, align: 0x100 }, mapping).unwrap();
    let alloc2 =
        mmu.alloc_memory(AllocLayout { addr: None, size: 0x100, align: 0x400 }, mapping).unwrap();
    let alloc3 =
        mmu.alloc_memory(AllocLayout { addr: None, size: 0x100, align: 0x800 }, mapping).unwrap();
    let alloc4 =
        mmu.alloc_memory(AllocLayout { addr: None, size: 0x100, align: 0x1000 }, mapping).unwrap();

    assert_eq!(mmu.get_perm(alloc1), perm::ALL);
    assert_eq!(mmu.get_perm(alloc2), perm::ALL);
    assert_eq!(mmu.get_perm(alloc3), perm::ALL);
    assert_eq!(mmu.get_perm(alloc4), perm::ALL);
}

#[test]
fn alloc_preferred_addr() {
    let mut mmu = Mmu::new();
    let mapping = Mapping { perm: perm::ALL, value: 0x0 };

    let alloc1 =
        mmu.alloc_memory(AllocLayout { addr: Some(0x1100), size: 0x100, align: 0x100 }, mapping);

    // Attempt to allocate already reserved address
    let alloc2 =
        mmu.alloc_memory(AllocLayout { addr: Some(0x1000), size: 0x1000, align: 0x100 }, mapping);

    // Preferred address has the incorrect alignment
    let alloc3 =
        mmu.alloc_memory(AllocLayout { addr: Some(0x2100), size: 0x100, align: 0x1000 }, mapping);

    eprintln!("{:#0x?}", mmu.get_mapping());

    assert_eq!(alloc1, Ok(0x1100));
    assert_eq!(alloc2, Ok(0x1200)); // alloc2 is points to the next free address of the correct size
    assert_eq!(alloc3, Ok(0x3000)); // alloc3 is aligned up
}

#[test]
fn multiple_instances() {
    let mut instances = [Mmu::new(), Mmu::new(), Mmu::new()];

    for (alloc_id, mmu) in instances.iter_mut().enumerate() {
        mmu.map_memory_len(0x0, 0x1000 * ITERATIONS, Mapping { perm: perm::NONE, value: 0xAA });
        for i in 0..ITERATIONS {
            let payload = [alloc_id as u8; 0x100];
            mmu.write_bytes(0x1000 * i, &payload, perm::NONE).unwrap();

            let mut output = [0x00; 0x100];
            mmu.read_bytes(0x1000 * i, &mut output, perm::INIT).unwrap();

            assert_eq!(&output[..], &payload[..])
        }
    }
}

#[test]
fn get_modified_pages() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x1000, 0x7000, Mapping { perm: perm::NONE, value: 0 });

    mmu.write_bytes(0x1000, &[0x12, 0x34], perm::NONE).unwrap();
    mmu.modified.clear();

    mmu.write_bytes(0x4000, &[0x12, 0x34], perm::NONE).unwrap();
    mmu.write_bytes(0x5000, &[0x12, 0x34], perm::NONE).unwrap();
    mmu.write_bytes(0x6000, &[0x12, 0x34], perm::NONE).unwrap();

    let mut modified: Vec<_> = mmu.modified.iter().copied().collect();
    modified.sort_unstable();

    eprintln!("modified: {:0x?}", modified);
    assert_eq!(modified, [0x4000, 0x5000, 0x6000]);
}

#[test]
fn snapshot_and_restore() {
    let mut mmu = Mmu::new();

    let test_addrs = [
        0x59a335e6, 0x49827709, 0x66b8c532, 0x384bcbd9, 0x22b123d0, 0x86caaab5, 0xc4881f6e,
        0x2db00047, 0xefd89ed4, 0x026f5adf, 0x06258d3a, 0xec7ee620, 0x00001000, 0x00002000,
        0x00003000, 0x00000000,
    ];

    // Write a fixed value to several test addresses
    for &addr in &test_addrs {
        let start = mmu.page_aligned(addr);
        mmu.map_memory_len(start, 0x1000, Mapping { perm: perm::NONE, value: 0 });
        mmu.write_bytes(addr, b"before", perm::NONE).unwrap()
    }

    eprintln!("initial={:#0x?}", mmu.get_mapping());

    // Take a snapshot of the current memory state
    let snapshot1 = mmu.snapshot();
    eprintln!("snapshot1 created");
    mmu.restore(snapshot1.clone());

    eprintln!("Restore [snapshot1]");
    mmu.restore(snapshot1.clone());
    eprintln!("Restore [snapshot1] done");

    // Overwrite the values written
    for &addr in &test_addrs {
        mmu.write_bytes(addr, b"after ", perm::NONE).unwrap()
    }

    eprintln!("after write={:#0x?}", mmu.get_mapping());

    // Test that we have overwritten the values successfully
    for &addr in &test_addrs {
        let mut out = [0; 6];
        mmu.read_bytes(addr, &mut out, perm::NONE).unwrap();
        assert_eq!(&out, b"after ");
    }
    let snapshot2 = mmu.snapshot();
    eprintln!("snapshot2 created");

    // Restore snapshot1 and test whether the original values have been restored
    mmu.restore(snapshot1.clone());
    eprintln!("snapshot1 restored");

    eprintln!("after [snapshot1]={:#0x?}", mmu.get_mapping());

    for &addr in &test_addrs {
        let mut out = [0; 6];
        mmu.read_bytes(addr, &mut out, perm::NONE).unwrap();
        assert_eq!(&out, b"before", "failed snapshot1 restore at: {:#0x}", addr);
    }

    // Restore snapshot1 and test whether the original values have been restored
    mmu.restore(snapshot2.clone());
    eprintln!("snapshot2 restored");

    eprintln!("after [snapshot2]={:#0x?}", mmu.get_mapping());

    for &addr in &test_addrs {
        let mut out = [0; 6];
        mmu.read_bytes(addr, &mut out, perm::NONE).unwrap();
        assert_eq!(&out, b"after ", "failed snapshot2 restore at: {:#0x}", addr);
    }
}

#[test]
fn snapshot_reset_and_restore() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x1000, 0x3000, Mapping { perm: perm::NONE, value: 0 });
    mmu.write_bytes(0x1000, b"before", perm::NONE).unwrap();
    mmu.write_bytes(0x3000, b"before", perm::NONE).unwrap();

    let before = mmu.snapshot();

    mmu.reset();
    mmu.map_memory_len(0x1000, 0x2000, Mapping { perm: perm::NONE, value: 0 });
    mmu.write_bytes(0x1000, b"after ", perm::NONE).unwrap();
    mmu.write_bytes(0x2000, b"after ", perm::NONE).unwrap();

    let after = mmu.snapshot();

    mmu.restore(before);

    let mut out = [0; 6];
    mmu.read_bytes(0x1000, &mut out, perm::NONE).unwrap();
    assert_eq!(&out, b"before");
    mmu.read_bytes(0x3000, &mut out, perm::NONE).unwrap();
    assert_eq!(&out, b"before");

    mmu.reset();
    mmu.restore(after);

    let mut out = [0; 6];
    mmu.read_bytes(0x1000, &mut out, perm::NONE).unwrap();
    assert_eq!(&out, b"after ");
    mmu.read_bytes(0x2000, &mut out, perm::NONE).unwrap();
    assert_eq!(&out, b"after ");
}

#[test]
fn complex_interactions() {
    let mut mmu = Mmu::new();

    // Request a large allocation that has an unaligned start and end.
    let alloc = mmu
        .alloc_memory(AllocLayout { addr: Some(0x1234), size: 0x8260, align: 0x1000 }, Mapping {
            perm: perm::READ | perm::MAP,
            value: 0xaa,
        })
        .unwrap();
    assert_eq!(alloc, 0x2000);

    // Check that the end of the page is marked as as unmapped
    assert_unmapped!(&mut mmu, 0x2000 + 0x8260);

    // Initialize and check first part of the allocation
    let data = [0x11; 0x4000];
    mmu.write_bytes(0x2000, &data, perm::NONE).unwrap();
    let mut out = [0x0; 0x4000];
    mmu.read_bytes(0x2000, &mut out, perm::INIT | perm::READ).unwrap();
    assert_eq!(data, out);

    // Set the rest of the allocation to zero
    mmu.fill_mem(0x6000, 0x4260, 0x0).unwrap();
    let mut out = [0xaa; 0x4260];
    mmu.read_bytes(0x6000, &mut out[..0x1000], perm::INIT | perm::READ).unwrap();
    mmu.read_bytes(0x7000, &mut out[0x1000..0x2000], perm::INIT | perm::READ).unwrap();
    mmu.read_bytes(0x8000, &mut out[0x2000..0x3000], perm::INIT | perm::READ).unwrap();
    mmu.read_bytes(0x9000, &mut out[0x3000..0x4000], perm::INIT | perm::READ).unwrap();
    mmu.read_bytes(0xa000, &mut out[0x4000..], perm::INIT | perm::READ).unwrap();
    assert!(out.iter().all(|x| *x == 0));

    // Update permissions of a region of memory within the allocation
    mmu.update_perm(0x4000, 0x4000, perm::NONE).unwrap();

    let none_perm = perm::MAP | if mmu.track_uninitialized { perm::NONE } else { perm::INIT };
    assert_eq!(perm::display(mmu.get_perm(0x4000)), perm::display(none_perm));
    assert_eq!(perm::display(mmu.get_perm(0x5000)), perm::display(none_perm));
    assert_eq!(perm::display(mmu.get_perm(0x6000)), perm::display(none_perm));
    assert_eq!(perm::display(mmu.get_perm(0x7000)), perm::display(none_perm));

    // Set some values in the ending partial page
    mmu.update_perm(0x8000, 0x260, perm::WRITE | perm::READ).unwrap();
    let data = [0x22; 0x260];
    mmu.write_bytes(0x8000, &data, perm::WRITE).unwrap();

    eprintln!("{:#0x?}", mmu.get_mapping());

    // Test that unmapping a range in the middle works
    mmu.unmap_memory_len(0x6000, 0x2000);
    assert_unmapped!(&mut mmu, 0x6000);
    assert_unmapped!(&mut mmu, 0x7000);

    eprintln!("{:#0x?}", mmu.get_mapping());

    // Check partial page at the end is still mapped
    let mut out = [0x0; 0x260];
    mmu.read_bytes(0x8000, &mut out, perm::INIT | perm::READ).unwrap();
    assert_eq!(out, [0x22; 0x260]);
}

#[test]
fn unmap_allocated() {
    let mut buf = [0; 16];
    let mut mmu = Mmu::new();

    mmu.map_memory_len(0x400000000, 0x3f0ae0, Mapping { perm: perm::READ, value: 0xaa });
    mmu.read_bytes(0x4003ed000, &mut buf, perm::NONE).unwrap();
    eprintln!("{:#0x?}", mmu.get_mapping());
    mmu.unmap_memory_len(0x4003ed000, 0x3f1000);
    eprintln!("{:#0x?}", mmu.get_mapping());

    let alloc_addr = mmu.alloc_memory(
        AllocLayout { addr: Some(0x4003ed000), size: 0x3ae0, align: 0x1000 },
        Mapping { perm: perm::READ, value: 0xaa },
    );
    assert_eq!(alloc_addr, Ok(0x4003ed000));
}

#[test]
fn move_memory() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x01000, 0x3000, Mapping { perm: perm::NONE, value: 0 });
    mmu.map_memory_len(0x04000, 0x4000, Mapping { perm: perm::NONE, value: 0 });
    mmu.map_memory_len(0x08000, 0x2000, Mapping { perm: perm::NONE, value: 1 });

    mmu.move_region_len(0x08000, 0x01000, 0x0).unwrap();

    let mut buf = [0; 16];
    mmu.read_bytes(0x0, &mut buf, perm::NONE).unwrap();
    assert_eq!(buf, [1; 16]);
}

#[test]
fn boundary_init() {
    let mut mmu = Mmu::new();
    mmu.map_memory_len(0x01000, 0x3000, Mapping { perm: perm::NONE, value: 0xaa });
    mmu.write(0x1000, [0xbb], perm::NONE).unwrap();

    let first = mmu.read::<1>(0x1000, perm::NONE).unwrap()[0];
    assert_eq!(first, 0xbb);
    let second = mmu.read::<1>(0x1001, perm::NONE).unwrap()[0];
    assert_eq!(second, 0xaa);
}
