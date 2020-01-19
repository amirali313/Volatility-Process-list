import volatility.utils as utils
import volatility.commands as commands
import volatility.obj as obj
import struct


class z_Plist(commands.Command):
	
	def render_text(self, outfd, data):
		pass

	def print_table(self):
		print("Offset"+ '\t\t' + '| ' 
			+ "Name" + '\t\t' + '| ' 
			+ 'PID' + '\t' + '| ' 
			+ 'PPID' + '\t' + '| ' 
			+ 'Thds' + '\t' + '| ' 
			+ 'Start')
		print('--------------- | ------------- | ----- | ----- | ----- | -----')

	def calculate(self):

		addrKPCR = 0xFFDFF000
		pointerToMiddle = 0x88

		addr_space = utils.load_as(self._config)

		_KPCR = obj.Object("_KPCR", addrKPCR, addr_space)

		_DBGKD_GET_VERSION64 = obj.Object("_DBGKD_GET_VERSION64", _KPCR.KdVersionBlock, addr_space)

		_LIST_ENTRY = obj.Object("_LIST_ENTRY", _DBGKD_GET_VERSION64.DebuggerDataList, addr_space)

		_KDDEBUGGER_DATA64 = obj.Object("_KDDEBUGGER_DATA64", _LIST_ENTRY.Flink, addr_space)

		_EPROCESS = obj.Object("_EPROCESS", _KDDEBUGGER_DATA64.PsActiveProcessHead - pointerToMiddle, addr_space)

		self.print_table()

		while True:
			nextAddr = _EPROCESS.ActiveProcessLinks.Flink
			if _KDDEBUGGER_DATA64.PsActiveProcessHead == nextAddr:
				break

			else:
				_EPROCESS = obj.Object("_EPROCESS", nextAddr - pointerToMiddle, addr_space)
				print(str(hex(int(nextAddr - pointerToMiddle))) + 
					'\t' + '| ' + str(_EPROCESS.ImageFileName) + 
					'\t' + '| ' + str(_EPROCESS.UniqueProcessId) + 
					'\t' + '| ' + str(_EPROCESS.InheritedFromUniqueProcessId) + 
					'\t' + '| ' + str(_EPROCESS.ActiveThreads) + 
					'\t' + '| ' + str(_EPROCESS.CreateTime))