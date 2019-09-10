import idaapi
import PyQt5, PyQt5.uic

class insnt_viewer_plugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_KEEP 
	comment = ""

	help = "Insnt_tView: Presents complete instruction information under cursor"
	wanted_name = "insn_t viewer"
	wanted_hotkey = ""
	website = ""
	
	last_ea = 0
	timer_obj = None
	viewer = None
	optype_tText = ["o_void", "o_reg", "o_mem", "o_phrase", "o_displ", "o_imm", "o_far", "o_near", "o_idspec0", "o_idspec1", "o_idspec2", "o_idspec3", "o_idspec4", "o_idspec5"]
	dtype_tText = ["dt_byte", "dt_word", "dt_dword", "dt_float", "dt_double", "dt_tbyte", "dt_packreal", "dt_qword", "dt_byte16", "dt_code", "dt_void", "dt_fword", "dt_bitfild", "dt_string", "dt_unicode", "dt_ldbl", "dt_byte32", "dt_byte64"]
	featuresList = ["CF_STOP", "CF_CALL", "CF_CHG1", "CF_CHG2", "CF_CHG3", "CF_CHG4", "CF_CHG5", "CF_CHG6", "CF_USE1", "CF_USE2", "CF_USE3", "CF_USE4", "CF_USE5", "CF_USE6", "CF_JUMP", "CF_SHFT", "CF_HLL", "CF_CHG7", "CF_CHG8", "CF_USE7", "CF_USE8"]
	insn = None
	i = 0

	def init(self):
		self.timer_obj = idaapi.register_timer(250, self.updateView)
		self.viewer = PyQt5.uic.loadUi("insnt_t_ui.ui")
		self.savedcloseEvent = self.viewer.closeEvent
		self.viewer.closeEvent = self.closeEvent
		
		self.viewer.show()
		self.viewer.auxpref_tree.topLevelItem(0).setExpanded(True)	
		self.viewer.auxpref_tree.topLevelItem(1).setExpanded(True)	
		self.viewer.auxpref_tree.topLevelItem(2).setExpanded(True)				
		self.viewer.optree.topLevelItem(0).setExpanded(True)		
		self.viewer.optree.topLevelItem(1).setExpanded(True)		
		self.viewer.optree.topLevelItem(2).setExpanded(True)		
		self.viewer.optree.topLevelItem(3).setExpanded(True)		
		self.viewer.optree.topLevelItem(4).setExpanded(True)		
		self.viewer.optree.topLevelItem(5).setExpanded(True)		
		self.viewer.optree.topLevelItem(6).setExpanded(True)		
		self.viewer.optree.topLevelItem(6).child(0).setExpanded(True)
		self.viewer.optree.topLevelItem(6).child(1).setExpanded(True)
		self.viewer.optree.topLevelItem(7).setExpanded(True)		
		self.viewer.optree.topLevelItem(8).setExpanded(True)		
		self.viewer.optree.topLevelItem(9).setExpanded(True)	
		
		self.viewer.optree.topLevelItem(9).child(0).setExpanded(True)		
		self.viewer.optree.topLevelItem(9).child(1).setExpanded(True)		
		self.viewer.optree.topLevelItem(9).child(2).setExpanded(True)		
		self.viewer.optree.topLevelItem(9).child(3).setExpanded(True)	

		self.viewer.operandSelector.currentChanged.connect(self.operandSelected)		

		return self.flags

	def updateView(self):
		ea = ScreenEA()
		if self.last_ea == ea:
			return 1
		self.last_ea = ea
		self.insn = DecodeInstruction(ea)
		v = self.viewer
		o = v.optree
		if self.insn == None:
			return 1
		# ---------------------------
		# Instruction data
		# ---------------------------
		v.cs_text.setPlainText(hex(self.insn.cs))
		v.ip_text.setPlainText(hex(self.insn.ip))
		v.ea_text.setPlainText(hex(self.insn.ea))
		v.segpref_text.setPlainText(hex(ord(self.insn.segpref)))
		v.insnpref_text.setPlainText(hex(ord(self.insn.insnpref)))
		v.flags_text.setPlainText(hex(self.insn.flags))
		v.itype_text.setPlainText(hex(self.insn.itype))
		
		# auxpref
		v.auxpref_tree.topLevelItem(0).child(0).setText(0, hex(self.insn.auxpref))
		
		# auxpref_u16
		v.auxpref_tree.topLevelItem(1).child(0).setText(0, hex((self.insn.auxpref & 0xFFFF0000) >> 16))
		v.auxpref_tree.topLevelItem(1).child(1).setText(0, hex(self.insn.auxpref & 0xFFFF))
		
		# auxpref_u8
		v.auxpref_tree.topLevelItem(2).child(0).setText(0, hex((self.insn.auxpref & 0xFF000000) >> 24))
		v.auxpref_tree.topLevelItem(2).child(1).setText(0, hex((self.insn.auxpref & 0x00FF0000) >> 16))
		v.auxpref_tree.topLevelItem(2).child(2).setText(0, hex((self.insn.auxpref & 0x0000FF00) >> 8))
		v.auxpref_tree.topLevelItem(2).child(3).setText(0, hex(self.insn.auxpref & 0x000000FF))
		
		# ---------------------------
		# Instruction data
		# ---------------------------
		for feature in self.featuresList:
			label = getattr(v, feature)
			label.setEnabled(False)
			
		
		features = self.insn.get_canon_feature()
		i = 0
		while features > 0:
			if features & 0x1:
				label = getattr(v, self.featuresList[i])
				label.setEnabled(True)
			i+= 1
			features = features >> 1
		
		# ---------------------------
		# Operand data
		# ---------------------------
		self.updateOperandTree()
		return 1

	def operandSelected(self, i):
		self.updateOperandTree()
		return

	def updateOperandTree(self):
		op = self.insn.ops[self.viewer.operandSelector.currentIndex()]
		o = self.viewer.optree
		
		o.topLevelItem(0).child(0).setText(0, str(op.n))
		o.topLevelItem(1).child(0).setText(0, self.optype_tText[op.type])
		o.topLevelItem(2).child(0).setText(0, str(op.offb))
		o.topLevelItem(3).child(0).setText(0, str(op.offo))
		self.updateOperandFlags(op.flags, o.topLevelItem(4))
		o.topLevelItem(5).child(0).setText(0, self.dtype_tText[op.dtype])
		o.topLevelItem(6).child(0).child(0).setText(0, hex(op.reg))
		o.topLevelItem(6).child(1).child(0).setText(0, hex(op.phrase))
		o.topLevelItem(7).child(0).setText(0, hex(op.value))
		o.topLevelItem(8).child(0).setText(0, hex(op.addr))
		
		o.topLevelItem(9).child(0).child(0).setText(0, hex(op.specflag1))
		o.topLevelItem(9).child(1).child(0).setText(0, hex(op.specflag2))
		o.topLevelItem(9).child(2).child(0).setText(0, hex(op.specflag3))
		o.topLevelItem(9).child(3).child(0).setText(0, hex(op.specflag4))
		return
		
	def updateOperandFlags(self, flags, node):
			node.child(0).setDisabled(flags & 0x80 == 0)
			node.child(1).setDisabled(flags & 0x40 == 0)
			node.child(2).setDisabled(flags & 0x20 == 0)
			node.child(3).setDisabled(flags & 0x10 == 0)
			node.child(4).setDisabled(flags & 0x8 == 0)
			return

	def run(self, arg):
		if self.timer_obj != None:
			return
		self.updateView()
		self.viewer.show()
		self.timer_obj = idaapi.register_timer(250, self.updateView)
		return

	def term(self):
		return

	def closeEvent(self, thing):
		self.savedcloseEvent(thing)
		idaapi.unregister_timer(self.timer_obj)
		self.timer_obj = None
		return

# For automatic plugin loading. Probably not needed when using the python REPL console in IDA.
def PLUGIN_ENTRY():
	return insnt_viewer_plugin()