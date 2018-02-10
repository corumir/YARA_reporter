import yara
import re
import collections
import sys
import json

class yararules():
	def __init__(self):
		self.name = []
		self.imports = []
		self.isGlobal = []
		self.isPrivate = []
		self.tags = []
		self.meta = []
		self.strings = []
		self.condition = []

	def stats(self):
		if not self.name:
			return "Stats not available on empty rule set"
		else:
			str_return = ["Total Rules: %d" % len(self.name)]
			str_return.append("Global: %d" % self.isGlobal.count(True))
			str_return.append("Private: %d" % self.isPrivate.count(True))

			#set variables
			import_count = {
				'pe': 0,
				'elf': 0,
				'cuckoo': 0,
				'magic': 0,
				'hash': 0,
				'math': 0,
			}
			str_total = []
			type_count = {
				'text': 0,
				'hex': 0,
				'regex': 0
			}
			mod_count = {
				'nocase': 0,
				'fullword': 0,
				'ascii': 0,
				'wide': 0
			}
			c_count = {
				'and': 0,
				'or': 0,
				'#': 0,
				'@': 0,
				'!': 0,
				'at': 0,
				'in': 0,
				'filesize': 0,
				'entrypoint': 0,
				'int': 0,
				'uint': 0,
				'of': 0,
				'for': 0,
			}
			c_regex = {
				'and': re.compile(r'\sand\s'),
				'or': re.compile(r'\sor\s'),
				'#': re.compile(r'\#'),
				'@': re.compile(r'\@'),
				'!': re.compile(r'\!'),
				'at': re.compile(r'\sat\s'),
				'in': re.compile(r'\sin\s'),
				'filesize': re.compile(r'filesize(?<![$#!])'),
				'entrypoint': re.compile(r'entrypoint'),
				'int': re.compile(r'int[0-9]+\(.*\)\s*=='),
				'uint': re.compile(r'uint[0-9]+\(.*\)\s*=='),
				'of': re.compile(r'\sof\s'),
				'for': re.compile(r'\sfor\s')
			}
			rule_total = []
			for i in range(len(self.strings)):

				#tally imports
				if 'pe' in self.imports[i]:
					import_count['pe'] += 1
				if 'elf' in self.imports[i]:
					import_count['elf'] += 1
				if 'cuckoo' in self.imports[i]:
					import_count['cuckoo'] += 1
				if 'magic' in self.imports[i]:
					import_count['magic'] += 1
				if 'hash' in self.imports[i]:
					import_count['hash'] += 1
				if 'math' in self.imports[i]:
					import_count['math'] += 1

				#Gather String data
				if self.strings[i]:
					for string in self.strings[i]:
						if string['type'] == 'text':
							type_count['text'] += 1
						elif string['type'] == 'hex':
							type_count['hex'] += 1
						elif string['type'] == 'regex':
							type_count['regex'] += 1
						if string['modifiers']:
							#string 'A' w/ modifiers is different than string 'A'
							str_total.append('%s %s' % (string['string'], ' '.join(string['modifiers'])))
							for mod in string['modifiers']:
								if mod == 'nocase':
									mod_count['nocase'] += 1
								elif mod == 'fullword':
									mod_count['fullword'] += 1
								elif mod == 'ascii':
									mod_count['ascii'] += 1
								elif mod == 'wide':
									mod_count['wide'] += 1
						else:
							str_total.append(string['string'])

				else:
					pass

				condition = self.condition[i]
				c_count['and'] += len(c_regex['and'].findall(condition))
				c_count['or'] += len(c_regex['or'].findall(condition))
				c_count['#'] += len(c_regex['#'].findall(condition))
				c_count['@'] += len(c_regex['@'].findall(condition))
				c_count['!'] += len(c_regex['!'].findall(condition))
				c_count['at'] += len(c_regex['at'].findall(condition))
				c_count['in'] += len(c_regex['in'].findall(condition))
				c_count['filesize'] += len(c_regex['filesize'].findall(condition))
				c_count['entrypoint'] += len(c_regex['entrypoint'].findall(condition))
				c_count['int'] += len(c_regex['int'].findall(condition))
				c_count['uint'] += len(c_regex['uint'].findall(condition))
				c_count['of'] += len(c_regex['of'].findall(condition))
				c_count['for'] += len(c_regex['for'].findall(condition))

			#Import print section
			str_return.append("Imports: %s-%s, %s-%s, %s-%s, %s-%s, %s-%s, %s-%s" % (
				'pe', import_count['pe'],
				'elf', import_count['elf'],
				'cuckoo', import_count['cuckoo'],
				'magic', import_count['magic'],
				'hash', import_count['hash'],
				'math', import_count['math']))

			#String print section
			str_counter = collections.Counter(str_total)
			str_return.append("\nTotal Strings: %d" % len(str_total))
			str_return.append("Type Count: text-%d, hex-%d, regex-%d " % (type_count['text'], type_count['hex'], type_count['regex']))
			str_return.append("Mod Count: nocase-%d, fullword-%d, ascii-%d, wide-%d" % (mod_count['nocase'], mod_count['fullword'], mod_count['ascii'], mod_count['wide']))
			str_return.append("Unique Strings: %d " % len(str_counter.keys()))
			str_return.append("Top 20 strings:")
			for pair in str_counter.most_common(20):
				str_return.append("%s: %d" % (pair[0], pair[1]))

			#Condtion print section
			str_return.append('\nCondition stats:')
			if c_count['and'] > 0:
				str_return.append('and: %d' % c_count['and'])
			if c_count['or'] > 0:
				str_return.append('or: %d' % c_count['or'])
			if c_count['#'] > 0:
				str_return.append('#: %d' % c_count['#'])
			if c_count['@'] > 0:
				str_return.append('@: %d' % c_count['@'])
			if c_count['!'] > 0:
				str_return.append('!: %d' % c_count['!'])
			if c_count['at'] > 0:
				str_return.append('at: %d' % c_count['at'])
			if c_count['in'] > 0:
				str_return.append('in: %d' % c_count['in'])
			if c_count['filesize'] > 0:
				str_return.append('filesize: %d' % c_count['filesize'])
			if c_count['entrypoint'] > 0:
				str_return.append('entrypoint: %d' % c_count['entrypoint'])
			if c_count['int'] > 0:
				str_return.append('int: %d' % c_count['int'])
			if c_count['uint'] > 0:
				str_return.append('uint: %d' % c_count['uint'])
			if c_count['of'] > 0:
				str_return.append('of: %d' % c_count['of'])
			if c_count['for'] > 0:
				str_return.append('for: %d' % c_count['for'])

			return '\n'.join(str_return)

	def buildYara(self, rulenames):
		if isinstance(rulenames, str):
			rulenames = [rulenames]

		ruleIndexes = []
		for rule in rulenames:
			if rule in self.name:
				ruleIndexes.append(self.name.index(rule))

		rules = []
		all_imports = []

		for i in ruleIndexes:
			rulename = self.name[i]
			imports = self.imports[i]
			glob = self.isGlobal[i]
			private = self.isPrivate[i]
			tags = self.tags[i]
			metadata = [(meta['name'], meta['content']) for meta in self.meta[i]]
			strings = [(string['name'], string['string'], string['modifiers']) for string in self.strings[i]]
			condition = self.condition[i]

			yararule = []
			if imports:
				for imp in imports:
					if imp in all_imports:
						pass
					else:
						all_imports.append(imp)

			if glob:
				yararule.append('global ')

			if private:
				yararule.append('private ')

			yararule.append('rule %s' % rulename)

			if tags:
				yararule.append(': %s' % ' '.join(tags))

			yararule.append('\n{\n')

			if metadata:
				yararule.append('\tmeta:\n')
				for meta in metadata:
					yararule.append('\t\t%s = %s\n' % (meta[0], meta[1]))

			if strings:
				yararule.append('\tstrings:\n')
				for string in strings:
					yararule.append('\t\t%s = %s' % (string[0], string[1]))
					if string[2]:
						yararule.append(' %s' % ' '.join(string[2]))
					yararule.append('\n')

			yararule.append('\tcondition:\n\t\t%s\n}\n\n' % condition)

			rules.extend(yararule)

		import_str = []
		for imp in all_imports:
			import_str.append('import "%s"\n' % imp)
		return ''.join(import_str) + ''.join(rules)

	def runYara(self, filepath, *args):
		if args:
			rulenames = args
		else:
			rulenames = self.name
		yaratext = self.buildYara(rulenames)
		yarac = yara.compile(source=yaratext)
		matches = yarac.match(filepath, callback=yara_callback)
		return [str(match) for match in matches]

def load(modelRules):
	yaraRules = yararules()
	for modelRule in modelRules:
		yaraRules.name.append(modelRule.name)
		yaraRules.imports.append([imp.name for imp in modelRule.import_set.all()])
		yaraRules.isGlobal.append(modelRule.isGlobal)
		yaraRules.isPrivate.append(modelRule.isPrivate)
		yaraRules.tags.append(modelRule.tags.split())
		yaraRules.meta.append(json.loads(modelRule.metadata))
		modelAliases = modelRule.alias.all()
		strings = []
		for modelAlias in modelAliases:
			modelString = modelAlias.string
			string = {
				'name': modelAlias.name,
				'string': modelString.string,
				'type': modelString.string_type,
			}
			modifiers = []
			if modelString.nocase:
				modifiers.append('nocase')
			if modelString.fullword:
				modifiers.append('fullword')
			if modelString.isAscii:
				modifiers.append('ascii')
			if modelString.wide:
				modifiers.append('wide')
			string['modifiers'] = modifiers
			strings.append(string)
		yaraRules.strings.append(strings)
		yaraRules.condition.append(modelRule.condition)
	return yaraRules

def parse(rawYara, compileCheck=True):
	if compileCheck:
		if not compile_check(rawYara):
			raise CompileError

	text = rawYara
	parsedRules = yararules()

	re_imports = re.compile(r'(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(import\s*\"(pe|elf|cuckoo|magic|hash|math)\")')
	re_rule = re.compile(r'(?:\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(?:\/(?:\\.|[^\/\\])*\/)|(global|private|rule.*?{)|(meta\s*:)|(strings\s*:)|(condition\s*:)', re.DOTALL | re.MULTILINE)
	re_meta = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(\w*\s*=)|(true|false)|([0-9])', re.DOTALL)
	re_string = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(nocase|fullword|ascii|wide)|({[A-Fa-f0-9\(\)\?\s\|\[\]\-]*})|(\/.*?\/)|(\$\w*\s*=\s*)', re.DOTALL)

	#find all imports
	import_matches = [n for n in re_imports.finditer(text)]
	all_imports = []
	replace_index = []
	for import_match in import_matches:
		if import_match.group(1):
			replace_index.append((import_match.start(1), import_match.end(1)))
			if not (import_match.group(2) in all_imports):
				all_imports.append(import_match.group(2))

	for (start_index, end_index) in reversed(replace_index):
		text = '%s%s'%(text[:start_index],text[end_index+1:])


	match = [n for n in re_rule.finditer(text)]

	# parse out global, private, rulename, tags, meta, strings, conditions
	rules = []
	meta = []
	string = []
	condition = []
	G = False
	P = False
	for i in range(len(match)):
		if match[i].group(1):
			if match[i].group(1) == 'global':
				G = True
			elif match[i].group(1) == 'private':
				P = True
			else:
				rule_split = match[i].group(1).split(':')
				if len(rule_split) > 1:
					tags = rule_split[-1].replace('{', '').split()
				else:
					tags = []
				rulename = rule_split[0].replace('{', '').split()[-1]

		if match[i].group(2): # meta
			start_index = match[i].end(2)
			n = 1
			try:
				while not(match[i+n].group(3) or match[i+n].group(4)):
					n += 1
				end_index = match[i+n].start(0)
				meta_matches = [n for n in re_meta.finditer(text, start_index, end_index)]

				for meta_match in meta_matches:
					if meta_match.group(2):
						meta_name = meta_match.group(2).replace('=', '').rstrip()
					else:
						meta_content = meta_match.group(0)
						meta.append({'name': meta_name, 'content': meta_content})

			except IndexError:
				continue

		if match[i].group(3): # strings
			start_index = match[i].end(3)
			n = 1
			try:
				while not(match[i+n].group(4)):
					n += 1
				end_index = match[i+n].start(0)
				string_match = [n for n in re_string.finditer(text, start_index, end_index)]

				for ii in range(len(string_match)):
					modifiers = []
					if string_match[ii].group(5): # name
						string_name = string_match[ii].group(5).replace('=', '').rstrip()
					elif string_match[ii].group(1): # text string
						string_type = 'text'
						string_content = string_match[ii].group(1)
						m = 1
						while string_match[ii+m].group(2):
							modifiers.append(string_match[ii+m].group(2))
							m += 1
							if (ii+m) >= len(string_match):
								break
						string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
					elif string_match[ii].group(3): # hex string
						string_type = 'hex'
						string_content = string_match[ii].group(3)
						string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
					elif string_match[ii].group(4): # regex string
						string_type = 'regex'
						string_content = string_match[ii].group(4)
						m = 1
						while string_match[ii+m].group(2):
							modifiers.append(string_match[ii+m].group(2))
							m += 1
							if (ii+m) >= len(string_match):
								break
						string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})

			except IndexError:
				string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
				continue

		if match[i].group(4): # condition
			start_index = match[i].end(4)
			n = 1
			try:
				while not(match[i+n].group(1)):
					n += 1
				end_index = match[i+n].start(0)
				condition = text[start_index:end_index].replace('}', '').strip()

			except IndexError:
				condition = text[start_index:].replace('}', '').strip()

			parsedRules.name.append(rulename)
			parsedRules.imports.append([imp for imp in all_imports if imp+'.' in condition])
			parsedRules.isGlobal.append(G)
			parsedRules.isPrivate.append(P)
			parsedRules.tags.append(tags)
			parsedRules.meta.append(meta)
			parsedRules.strings.append(string)
			parsedRules.condition.append(condition)

			G = False
			P = False
			meta = []
			string = []

	return parsedRules

def yara_callback(data):
	return yara.CALLBACK_CONTINUE

def compile_check(rawYara):
	try:
		yara.compile(source=rawYara)
		return True
	except yara.SyntaxError:
		return False

class CompileError(Exception):
	pass
