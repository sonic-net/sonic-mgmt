"""Keep these descriptors separate from other clients' gNMI schema versions."""

from google.protobuf import any_pb2, descriptor_pb2, descriptor_pool

POOL = descriptor_pool.DescriptorPool()
POOL.AddSerializedFile(any_pb2.DESCRIPTOR.serialized_pb)
POOL.AddSerializedFile(descriptor_pb2.DESCRIPTOR.serialized_pb)
