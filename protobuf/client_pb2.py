# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protobuf/client.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='protobuf/client.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x15protobuf/client.proto\"\x8a\x01\n\x10\x43lientAttributes\x12\x14\n\x0cuser_address\x18\x01 \x01(\t\x12\x13\n\x0btrust_score\x18\x02 \x01(\x05\x12\x1b\n\x13pointer_to_registry\x18\x03 \x01(\t\x12\x19\n\x11registration_link\x18\x04 \x01(\t\x12\x13\n\x0b\x66\x61mily_name\x18\x05 \x01(\t\"D\n\x1a\x43lientInfoSetupTransaction\x12&\n\x0b\x63lient_info\x18\x01 \x01(\x0b\x32\x11.ClientAttributes\"6\n\x16StateUpdateTransaction\x12\x0e\n\x06\x61\x63tion\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x62\x06proto3')
)




_CLIENTATTRIBUTES = _descriptor.Descriptor(
  name='ClientAttributes',
  full_name='ClientAttributes',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='user_address', full_name='ClientAttributes.user_address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='trust_score', full_name='ClientAttributes.trust_score', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pointer_to_registry', full_name='ClientAttributes.pointer_to_registry', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='registration_link', full_name='ClientAttributes.registration_link', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='family_name', full_name='ClientAttributes.family_name', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=26,
  serialized_end=164,
)


_CLIENTINFOSETUPTRANSACTION = _descriptor.Descriptor(
  name='ClientInfoSetupTransaction',
  full_name='ClientInfoSetupTransaction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='client_info', full_name='ClientInfoSetupTransaction.client_info', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=166,
  serialized_end=234,
)


_STATEUPDATETRANSACTION = _descriptor.Descriptor(
  name='StateUpdateTransaction',
  full_name='StateUpdateTransaction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='action', full_name='StateUpdateTransaction.action', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='data', full_name='StateUpdateTransaction.data', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=236,
  serialized_end=290,
)

_CLIENTINFOSETUPTRANSACTION.fields_by_name['client_info'].message_type = _CLIENTATTRIBUTES
DESCRIPTOR.message_types_by_name['ClientAttributes'] = _CLIENTATTRIBUTES
DESCRIPTOR.message_types_by_name['ClientInfoSetupTransaction'] = _CLIENTINFOSETUPTRANSACTION
DESCRIPTOR.message_types_by_name['StateUpdateTransaction'] = _STATEUPDATETRANSACTION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ClientAttributes = _reflection.GeneratedProtocolMessageType('ClientAttributes', (_message.Message,), {
  'DESCRIPTOR' : _CLIENTATTRIBUTES,
  '__module__' : 'protobuf.client_pb2'
  # @@protoc_insertion_point(class_scope:ClientAttributes)
  })
_sym_db.RegisterMessage(ClientAttributes)

ClientInfoSetupTransaction = _reflection.GeneratedProtocolMessageType('ClientInfoSetupTransaction', (_message.Message,), {
  'DESCRIPTOR' : _CLIENTINFOSETUPTRANSACTION,
  '__module__' : 'protobuf.client_pb2'
  # @@protoc_insertion_point(class_scope:ClientInfoSetupTransaction)
  })
_sym_db.RegisterMessage(ClientInfoSetupTransaction)

StateUpdateTransaction = _reflection.GeneratedProtocolMessageType('StateUpdateTransaction', (_message.Message,), {
  'DESCRIPTOR' : _STATEUPDATETRANSACTION,
  '__module__' : 'protobuf.client_pb2'
  # @@protoc_insertion_point(class_scope:StateUpdateTransaction)
  })
_sym_db.RegisterMessage(StateUpdateTransaction)


# @@protoc_insertion_point(module_scope)
