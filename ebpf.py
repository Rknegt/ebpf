from typing import Iterable

from volatility3.framework import interfaces, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins


KERNEL_UID32_T_SIZE = 2


class Ebpf(plugins.PluginInterface):
    """
    List all the bpf programs with additional info
    """

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="disassembly",
                description="Show disassembly",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="id",
                description="Filter on specific bpf_program IDs",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="basefull",
                description="Set to false if CONFIG_BASE_FULL is disabled in kernel, default is enabled",
                default=True,
                optional=True,
            ),
        ]

    @classmethod
    def get_ebpf_programs(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        id: int = None,
        config_base_full: bool = True,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Return an iterator that yields 2 objects, the bpf_prog and the corresponding
        bpf_prog_aux of that bpf program.


        context -- The context object, necessary for obtaining other modules/objects
        vmlinux_module_name -- Name of the kernel module
        id -- If present this only returns the bpf_program with this specific ID
        """
        vm_linux = context.modules[vmlinux_module_name]

        """ The prog_idr symbol contains all the related kernel structures of the bpf_progs """
        prog_idr = vm_linux.object_from_symbol(symbol_name="prog_idr")

        default_symbol = vm_linux.symbol_table_name + constants.BANG

        """ Get the xa_node inside the xarray of the prog_idr.
        This object contains another array that stores the pointers to the bpf_progs. """
        xa_node = context.object(
            default_symbol + "xa_node",
            offset=prog_idr.idr_rt.xa_head,
            layer_name=vm_linux.layer_name,
        )

        """ Because of the shift we need to substract 1 of the length. """
        length = len(xa_node.slots) - 1

        """ Determine how many bytes array is shifted, this depends on the
        CONFIG_BASE_FULL kernel parameter. """
        if config_base_full:
            shift = 6
        else:
            shift = 4

        """ The slots array holds all the pointers to the bpf_progs. """
        slots_array = context.object(
            default_symbol + "array",
            layer_name=vm_linux.layer_name,
            offset=xa_node.slots.vol.offset + shift,
            subtype=context.symbol_space.get_type(
                vm_linux.symbol_table_name + constants.BANG + "pointer"
            ),
            count=length,
        )

        for i in range(length):
            bpf_prog = context.object(
                default_symbol + "bpf_prog",
                offset=slots_array[i],
                layer_name=vm_linux.layer_name,
            )
            """ Check if the pointer points to a valid bpf_prog """
            if bpf_prog.vol.offset == 0:
                continue

            bpf_prog_aux = context.object(
                default_symbol + "bpf_prog_aux",
                offset=bpf_prog.aux,
                layer_name=vm_linux.layer_name,
            )

            if id and id != bpf_prog_aux.id:
                continue

            yield bpf_prog, bpf_prog_aux

    def _generator(self, bpf_progs, show_disassembly: bool):
        """Yield all the bpf programs with their additional information

        Arguments:
        bpf_progs -- Iterator of bpf programs
        show_disassembly -- Get the assembly instructions of bpf programs
        """
        vm_linux = self.context.modules[self.config["kernel"]]
        default_symbol = vm_linux.symbol_table_name + constants.BANG

        """ Set the architecture to 32 bit or 64 bit """
        if symbols.symbol_table_is_64bit(self.context, vm_linux.symbol_table_name):
            arch = "intel64"
        else:
            arch = "intel32"

        for bpf_prog, bpf_prog_aux in bpf_progs:
            bpf_prog_loc = str(hex(bpf_prog.vol.offset))

            aux_loc = str(hex(bpf_prog.aux))

            bpf_prog_id = bpf_prog_aux.id

            user = self.context.object(
                default_symbol + "user_struct",
                offset=bpf_prog_aux.user,
                layer_name=vm_linux.layer_name,
            )

            """Read the UID from the user_struct in bytes because we can't access it through objects. """
            uid = int.from_bytes(
                self._context.layers[vm_linux.layer_name].read(
                    user.uid.vol.offset, KERNEL_UID32_T_SIZE
                ),
                "little",
            )

            """ Read the assembly instructions of the bpf program as bytes. """
            bpf_func_data = self._context.layers[vm_linux.layer_name].read(
                bpf_prog.bpf_func, bpf_prog.jited_len
            )

            """Show the assembly instructions from the bpf_func with the disassembly renderer. """
            if show_disassembly:
                disasm = interfaces.renderers.Disassembly(
                    bpf_func_data, bpf_prog.bpf_func, arch
                )
                yield (0, (bpf_prog_id, bpf_prog_loc, aux_loc, uid, disasm))
            else:
                yield (0, (bpf_prog_id, bpf_prog_loc, aux_loc, uid))

    def run(self):
        disassembly = self.config.get("disassembly")
        id = self.config.get("id")
        config_base_full = self.config.get("basefull")

        columns = [
            ("ID", int),
            ("BPF_PROGRAM", str),
            ("AUX", str),
            ("UID", int),
        ]

        if disassembly:
            columns.append(("Disasm", interfaces.renderers.Disassembly))

        return renderers.TreeGrid(
            columns,
            self._generator(
                self.get_ebpf_programs(
                    context=self.context,
                    vmlinux_module_name=self.config["kernel"],
                    id=id,
                    config_base_full=config_base_full,
                ),
                show_disassembly=disassembly,
            ),
        )
