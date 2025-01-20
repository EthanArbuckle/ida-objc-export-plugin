import ida_hexrays
import ida_lines
import ida_idaapi
import ida_kernwin


class objc_line_format_t:

    @staticmethod
    def is_assigment(line: str) -> bool:
        return line.find(" = ") != -1 and line.rstrip().endswith(";")

    @staticmethod
    def is_unassigned_variable_declaration(line: str) -> bool:
        return line.find(" = ") == -1 and line.rstrip().endswith(";")

    def transform_objc_retainAutoreleasedReturnValue(self, line: str) -> str:
        if "objc_retainAutoreleasedReturnValue(" not in line:
            return line

        new_line = line.replace("objc_retainAutoreleasedReturnValue(", "").replace(");", ";")
        parts = new_line.split(" = ")
        if len(parts) == 2 and parts[0].strip() == parts[1].strip():
            return ""

        return new_line

    def transform_objc_autoreleasePoolPush(self, line: str) -> str:
        if "objc_autoreleasePoolPush();" not in line:
            return line
        return ""

    def transform_objc_storeStrong_assignment(self, line: str) -> str:
        # objc_storeStrong(&var, value) -> var = value;
        if "objc_storeStrong(&" not in line:
            return line
        return line.replace("objc_storeStrong(&", "").replace(", ", " = ").replace(");", ";")

    def transform_objc_autoreleasePoolPop(self, line: str) -> str:
        if "objc_autoreleasePoolPop(" not in line:
            return line
        return ""

    def transform_objc_release_assignment(self, line: str) -> str:
        # objc_release(var) -> var = nil;
        if "objc_release(" not in line:
            return line
        return ""
        return line.replace("objc_release(", "").replace(");", " = nil;")

    def transform_objc_opt_class(self, line: str) -> str:
        if "objc_opt_class(&OBJC_CLASS___" not in line:
            return line
        p1 = line.replace("objc_opt_class(&OBJC_CLASS___", "").replace(");", ";")
        # now in: `<anytype> v131 = NSURL;`
        p2_without_type = p1.split(" ", 1)[1]
        # now in: `v131 = NSURL;`
        p2 = p2_without_type.replace(" = ", " = [").replace(";", " class];")
        # now in: `v131 = [NSURL class];`
        p2_with_class_type = "Class " + p2.lstrip()
        # now in: `Class v131 = [NSURL class];`
        return p2_with_class_type

    def get_transforms(self):
        return [
            self.transform_objc_storeStrong_assignment,
            self.transform_objc_release_assignment,
            self.transform_objc_autoreleasePoolPush,
            self.transform_objc_autoreleasePoolPop,
            self.transform_objc_opt_class,
            self.transform_objc_retainAutoreleasedReturnValue,
        ]


class objc_cleaner_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)

    def func_printed(self, cfunc):
        lines = cfunc.get_pseudocode()

        i = 0
        while i < len(lines):
            line = lines[i]
            if not line or not line.line:
                i += 1
                continue

            print(f"* {line.line}")
            line_text = line.line  # ida_lines.tag_remove(line.line)
            line_initial_indent = line_text[: len(line_text) - len(line_text.lstrip())]

            for check_method_func in objc_line_format_t().get_transforms():
                try:
                    new_line_text = check_method_func(line_text)
                    if new_line_text == line_text:
                        continue

                    if new_line_text is None:
                        print(f"removing line: {line_text}")
                        lines[i].line = None
                        break

                    print(f"keeping transformed line: {new_line_text}")
                    new_line_text = line_initial_indent + new_line_text.lstrip()

                    lines[i].line = new_line_text

                except Exception as e:
                    print(f"Error transforming line: {e}")
                    continue

            i += 1
        return 0


class objc_cleaner_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    wanted_name = "Hex-Rays Objective-C Memory Management Cleaner"
    wanted_hotkey = ""
    comment = "Removes objc_release and objc_storeStrong calls from pseudocode"
    help = "Automatically removes lines containing only objc_release or objc_storeStrong calls"

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.hooks = objc_cleaner_hooks_t()
            self.hooks.hook()
            print(f"{self.wanted_name}: Successfully initialized")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self.hooks.unhook()
        print(f"{self.wanted_name}: Terminated")

    def run(self, arg):
        if not ida_hexrays.init_hexrays_plugin():
            return


def PLUGIN_ENTRY():
    return objc_cleaner_plugin_t()
