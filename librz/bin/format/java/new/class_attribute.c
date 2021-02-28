// SPDX-License-Identifier: LGPL-3.0-only

#include "class_attribute.h"

/*
ConstantValue                           45.3 // Java SE 1.0.2
Code                                    45.3 // Java SE 1.0.2
StackMapTable                           50.0 // Java SE 6
Exceptions                              45.3 // Java SE 1.0.2
InnerClasses                            45.3 // Java SE 1.1
EnclosingMethod                         49.0 // Java SE 5.0
Synthetic                               45.3 // Java SE 1.1
Signature                               49.0 // Java SE 5.0
SourceFile                              45.3 // Java SE 1.0.2
SourceDebugExtension                    49.0 // Java SE 5.0
LineNumberTable                         45.3 // Java SE 1.0.2
LocalVariableTable                      45.3 // Java SE 1.0.2
LocalVariableTypeTable                  49.0 // Java SE 5.0
Deprecated                              45.3 // Java SE 1.1
RuntimeVisibleAnnotations               49.0 // Java SE 5.0
RuntimeInvisibleAnnotations             49.0 // Java SE 5.0
RuntimeVisibleParameterAnnotations      49.0 // Java SE 5.0
RuntimeInvisibleParameterAnnotations    49.0 // Java SE 5.0
RuntimeVisibleTypeAnnotations           52.0 // Java SE 8
RuntimeInvisibleTypeAnnotations         52.0 // Java SE 8
AnnotationDefault                       49.0 // Java SE 5.0
BootstrapMethods                        51.0 // Java SE 7
MethodParameters                        52.0 // Java SE 8
Module                                  53.0 // Java SE 9
ModulePackages                          53.0 // Java SE 9
ModuleMainClass                         53.0 // Java SE 9
NestHost                                55.0 // Java SE 11
NestMembers                             55.0 // Java SE 11
*/

static ut8 *copy_buffer(RzBuffer *buf, st64 size) {
	ut8 *buffer = (ut8 *)malloc(size);
	if (!buffer || rz_buf_read(buf, buffer, size) < (size - 1)) {
		rz_warn_if_reached();
		free(buffer);
		return NULL;
	}
	return buffer;
}

static char* resolve_const_pool_index(ConstPool **pool, ut32 poolsize, ut32 index) {
	const ConstPool *cpool;
	if (index >= poolsize || !(cpool = pool[index])) {
		return NULL;
	}
	return java_constant_pool_stringify(cpool);
}

bool java_attribute_set_unknown(Attribute *attr, RzBuffer *buf) {
	attr->type = ATTRIBUTE_TYPE_UNKNOWN;
	if (attr->attribute_length < 1) {
		return true;
	}
	st64 size = (st64)attr->attribute_length;
	attr->info = copy_buffer(buf, size);
	return true;
}

bool java_attribute_set_constantvalue(Attribute *attr, RzBuffer *buf) {
	rz_warn_if_fail(attr->attribute_length == 2);
	AttributeConstantValue *acv = RZ_NEW0(AttributeConstantValue);
	if (!acv) {
		return false;
	}
	acv->index = rz_buf_read_be16(buf);
	attr->type = ATTRIBUTE_TYPE_CONSTANTVALUE;
	attr->info = (void *)acv;
	return true;
}

bool java_attribute_set_code(ConstPool **pool, ut32 poolsize, Attribute *attr, RzBuffer *buf) {
	AttributeCode *ac = RZ_NEW0(AttributeCode);
	if (!ac) {
		rz_warn_if_reached();
		return false;
	}
	ac->max_stack = rz_buf_read_be16(buf);
	ac->max_locals = rz_buf_read_be16(buf);
	ac->code_length = rz_buf_read_be32(buf);
	ac->code_offset = attr->offset + 14; // 6 bytes for attribute + 8 as code
	ac->code = copy_buffer(buf, ac->code_length);
	if (!ac->code) {
		free(ac);
		rz_warn_if_reached();
		return false;
	}
	ac->exceptions_count = rz_buf_read_be16(buf);
	if (ac->exceptions_count > 0) {
		ac->exceptions = RZ_NEWS0(ExceptionTable, ac->exceptions_count);
		if (!ac->exceptions) {
			free(ac->code);
			free(ac);
			rz_warn_if_reached();
			return false;
		}
		for (ut32 i = 0; i < ac->exceptions_count; ++i) {
			ac->exceptions[i].start_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].end_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].handler_pc = rz_buf_read_be16(buf);
			ac->exceptions[i].catch_type = rz_buf_read_be16(buf);
		}
	}

	ac->attributes_count = rz_buf_read_be16(buf);
	if (ac->attributes_count > 0) {
		ac->attributes = RZ_NEWS0(Attribute *, ac->attributes_count);
		if (!ac->attributes) {
			free(ac->exceptions);
			free(ac->code);
			free(ac);
			rz_warn_if_reached();
			return NULL;
		}

		for (ut32 i = 0; i < ac->attributes_count; ++i) {
			Attribute *attr = java_attribute_new(buf, UT64_MAX);
			if(attr && java_attribute_resolve(pool, poolsize, attr, buf)) {
				ac->attributes[i] = attr;
			} else {
				java_attribute_free(attr);
			}
		}
	}

	attr->type = ATTRIBUTE_TYPE_CODE;
	attr->info = (void *)ac;
	return true;
}

bool java_attribute_resolve(ConstPool **pool, ut32 poolsize, Attribute *attr, RzBuffer *buf) {
	char *name = resolve_const_pool_index(pool, poolsize, attr->attribute_name_index);
	if (!name) {
		return false;
	}

	bool result = false;
	if (!strcmp(name, "ConstantValue")) {
		result = java_attribute_set_constantvalue(attr, buf);
	} else if (!strcmp(name, "Code")) {
		result = java_attribute_set_code(pool, poolsize, attr, buf);
	}
	/*
		else if (!strcmp(name, "StackMapTable")) {
			result = java_attribute_set_stackmaptable(attr, buf);
		} else if (!strcmp(name, "Exceptions")) {
			result = java_attribute_set_exceptions(attr, buf);
		} else if (!strcmp(name, "InnerClasses")) {
			result = java_attribute_set_innerclasses(attr, buf);
		} else if (!strcmp(name, "EnclosingMethod")) {
			result = java_attribute_set_enclosingmethod(attr, buf);
		} else if (!strcmp(name, "Synthetic")) {
			result = java_attribute_set_synthetic(attr, buf);
		} else if (!strcmp(name, "Signature")) {
			result = java_attribute_set_signature(attr, buf);
		} else if (!strcmp(name, "SourceFile")) {
			result = java_attribute_set_sourcefile(attr, buf);
		} else if (!strcmp(name, "SourceDebugExtension")) {
			result = java_attribute_set_sourcedebugextension(attr, buf);
		} else if (!strcmp(name, "LineNumberTable")) {
			result = java_attribute_set_linenumbertable(attr, buf);
		} else if (!strcmp(name, "LocalVariableTable")) {
			result = java_attribute_set_localvariabletable(attr, buf);
		} else if (!strcmp(name, "LocalVariableTypeTable")) {
			result = java_attribute_set_localvariabletypetable(attr, buf);
		} else if (!strcmp(name, "Deprecated")) {
			result = java_attribute_set_deprecated(attr, buf);
		} else if (!strcmp(name, "RuntimeVisibleAnnotations")) {
			result = java_attribute_set_runtimevisibleannotations(attr, buf);
		} else if (!strcmp(name, "RuntimeInvisibleAnnotations")) {
			result = java_attribute_set_runtimeinvisibleannotations(attr, buf);
		} else if (!strcmp(name, "RuntimeVisibleParameterAnnotations")) {
			result = java_attribute_set_runtimevisibleparameterannotations(attr, buf);
		} else if (!strcmp(name, "RuntimeInvisibleParameterAnnotations")) {
			result = java_attribute_set_runtimeinvisibleparameterannotations(attr, buf);
		} else if (!strcmp(name, "RuntimeVisibleTypeAnnotations")) {
			result = java_attribute_set_runtimevisibletypeannotations(attr, buf);
		} else if (!strcmp(name, "RuntimeInvisibleTypeAnnotations")) {
			result = java_attribute_set_runtimeinvisibletypeannotations(attr, buf);
		} else if (!strcmp(name, "AnnotationDefault")) {
			result = java_attribute_set_annotationdefault(attr, buf);
		} else if (!strcmp(name, "BootstrapMethods")) {
			result = java_attribute_set_bootstrapmethods(attr, buf);
		} else if (!strcmp(name, "MethodParameters")) {
			result = java_attribute_set_methodparameters(attr, buf);
		} else if (!strcmp(name, "Module")) {
			result = java_attribute_set_module(attr, buf);
		} else if (!strcmp(name, "ModulePackages")) {
			result = java_attribute_set_modulepackages(attr, buf);
		} else if (!strcmp(name, "ModuleMainClass")) {
			result = java_attribute_set_modulemainclass(attr, buf);
		} else if (!strcmp(name, "NestHost")) {
			result = java_attribute_set_nesthost(attr, buf);
		} else if (!strcmp(name, "NestMembers")) {
			result = java_attribute_set_nestmembers(attr, buf);
		}
	*/
	if (!result) {
		result = java_attribute_set_unknown(attr, buf);
	}
	free(name);
	return result;
}

Attribute *java_attribute_new(RzBuffer *buf, ut64 offset) {
	Attribute *attr = RZ_NEW0(Attribute);
	rz_return_val_if_fail(attr, NULL);
	attr->offset = offset;
	attr->attribute_name_index = rz_buf_read_be16(buf);
	ut32 attribute_length = 0;
	attribute_length = rz_buf_read_be16(buf) << 16;
	attribute_length |= rz_buf_read_be16(buf);
	if (attribute_length == UT32_MAX) {
		free(attr);
		return NULL;
	}
	attr->attribute_length = attribute_length;
	return attr;
}

void java_attribute_free(Attribute *attr) {
	if (!attr || !attr->info) {
		free(attr);
		return;
	}
	if (attr->type == ATTRIBUTE_TYPE_CODE) {
		AttributeCode *ac = (AttributeCode *)attr->info;
		free(ac->code);
		free(ac->exceptions);
		if (ac->attributes) {
			for (ut32 i = 0; i < ac->attributes_count; ++i) {
				java_attribute_free(ac->attributes[i]);
			}
			free(ac->attributes);
		}
	}
	free(attr->info);
	free(attr);
}
