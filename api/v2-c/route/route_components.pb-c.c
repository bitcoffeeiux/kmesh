/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: api/route/route_components.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "route/route_components.pb-c.h"
void   route__virtual_host__init
                     (Route__VirtualHost         *message)
{
  static const Route__VirtualHost init_value = ROUTE__VIRTUAL_HOST__INIT;
  *message = init_value;
}
size_t route__virtual_host__get_packed_size
                     (const Route__VirtualHost *message)
{
  assert(message->base.descriptor == &route__virtual_host__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__virtual_host__pack
                     (const Route__VirtualHost *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__virtual_host__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__virtual_host__pack_to_buffer
                     (const Route__VirtualHost *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__virtual_host__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__VirtualHost *
       route__virtual_host__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__VirtualHost *)
     protobuf_c_message_unpack (&route__virtual_host__descriptor,
                                allocator, len, data);
}
void   route__virtual_host__free_unpacked
                     (Route__VirtualHost *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__virtual_host__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__route__init
                     (Route__Route         *message)
{
  static const Route__Route init_value = ROUTE__ROUTE__INIT;
  *message = init_value;
}
size_t route__route__get_packed_size
                     (const Route__Route *message)
{
  assert(message->base.descriptor == &route__route__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__route__pack
                     (const Route__Route *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__route__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__route__pack_to_buffer
                     (const Route__Route *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__route__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__Route *
       route__route__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__Route *)
     protobuf_c_message_unpack (&route__route__descriptor,
                                allocator, len, data);
}
void   route__route__free_unpacked
                     (Route__Route *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__route__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__route_match__init
                     (Route__RouteMatch         *message)
{
  static const Route__RouteMatch init_value = ROUTE__ROUTE_MATCH__INIT;
  *message = init_value;
}
size_t route__route_match__get_packed_size
                     (const Route__RouteMatch *message)
{
  assert(message->base.descriptor == &route__route_match__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__route_match__pack
                     (const Route__RouteMatch *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__route_match__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__route_match__pack_to_buffer
                     (const Route__RouteMatch *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__route_match__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__RouteMatch *
       route__route_match__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__RouteMatch *)
     protobuf_c_message_unpack (&route__route_match__descriptor,
                                allocator, len, data);
}
void   route__route_match__free_unpacked
                     (Route__RouteMatch *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__route_match__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__route_action__hash_policy__header__init
                     (Route__RouteAction__HashPolicy__Header         *message)
{
  static const Route__RouteAction__HashPolicy__Header init_value = ROUTE__ROUTE_ACTION__HASH_POLICY__HEADER__INIT;
  *message = init_value;
}
void   route__route_action__hash_policy__init
                     (Route__RouteAction__HashPolicy         *message)
{
  static const Route__RouteAction__HashPolicy init_value = ROUTE__ROUTE_ACTION__HASH_POLICY__INIT;
  *message = init_value;
}
void   route__route_action__init
                     (Route__RouteAction         *message)
{
  static const Route__RouteAction init_value = ROUTE__ROUTE_ACTION__INIT;
  *message = init_value;
}
size_t route__route_action__get_packed_size
                     (const Route__RouteAction *message)
{
  assert(message->base.descriptor == &route__route_action__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__route_action__pack
                     (const Route__RouteAction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__route_action__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__route_action__pack_to_buffer
                     (const Route__RouteAction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__route_action__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__RouteAction *
       route__route_action__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__RouteAction *)
     protobuf_c_message_unpack (&route__route_action__descriptor,
                                allocator, len, data);
}
void   route__route_action__free_unpacked
                     (Route__RouteAction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__route_action__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__retry_policy__init
                     (Route__RetryPolicy         *message)
{
  static const Route__RetryPolicy init_value = ROUTE__RETRY_POLICY__INIT;
  *message = init_value;
}
size_t route__retry_policy__get_packed_size
                     (const Route__RetryPolicy *message)
{
  assert(message->base.descriptor == &route__retry_policy__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__retry_policy__pack
                     (const Route__RetryPolicy *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__retry_policy__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__retry_policy__pack_to_buffer
                     (const Route__RetryPolicy *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__retry_policy__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__RetryPolicy *
       route__retry_policy__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__RetryPolicy *)
     protobuf_c_message_unpack (&route__retry_policy__descriptor,
                                allocator, len, data);
}
void   route__retry_policy__free_unpacked
                     (Route__RetryPolicy *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__retry_policy__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__weighted_cluster__init
                     (Route__WeightedCluster         *message)
{
  static const Route__WeightedCluster init_value = ROUTE__WEIGHTED_CLUSTER__INIT;
  *message = init_value;
}
size_t route__weighted_cluster__get_packed_size
                     (const Route__WeightedCluster *message)
{
  assert(message->base.descriptor == &route__weighted_cluster__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__weighted_cluster__pack
                     (const Route__WeightedCluster *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__weighted_cluster__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__weighted_cluster__pack_to_buffer
                     (const Route__WeightedCluster *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__weighted_cluster__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__WeightedCluster *
       route__weighted_cluster__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__WeightedCluster *)
     protobuf_c_message_unpack (&route__weighted_cluster__descriptor,
                                allocator, len, data);
}
void   route__weighted_cluster__free_unpacked
                     (Route__WeightedCluster *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__weighted_cluster__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__cluster_weight__init
                     (Route__ClusterWeight         *message)
{
  static const Route__ClusterWeight init_value = ROUTE__CLUSTER_WEIGHT__INIT;
  *message = init_value;
}
size_t route__cluster_weight__get_packed_size
                     (const Route__ClusterWeight *message)
{
  assert(message->base.descriptor == &route__cluster_weight__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__cluster_weight__pack
                     (const Route__ClusterWeight *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__cluster_weight__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__cluster_weight__pack_to_buffer
                     (const Route__ClusterWeight *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__cluster_weight__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__ClusterWeight *
       route__cluster_weight__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__ClusterWeight *)
     protobuf_c_message_unpack (&route__cluster_weight__descriptor,
                                allocator, len, data);
}
void   route__cluster_weight__free_unpacked
                     (Route__ClusterWeight *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__cluster_weight__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   route__header_matcher__init
                     (Route__HeaderMatcher         *message)
{
  static const Route__HeaderMatcher init_value = ROUTE__HEADER_MATCHER__INIT;
  *message = init_value;
}
size_t route__header_matcher__get_packed_size
                     (const Route__HeaderMatcher *message)
{
  assert(message->base.descriptor == &route__header_matcher__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t route__header_matcher__pack
                     (const Route__HeaderMatcher *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &route__header_matcher__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t route__header_matcher__pack_to_buffer
                     (const Route__HeaderMatcher *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &route__header_matcher__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Route__HeaderMatcher *
       route__header_matcher__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Route__HeaderMatcher *)
     protobuf_c_message_unpack (&route__header_matcher__descriptor,
                                allocator, len, data);
}
void   route__header_matcher__free_unpacked
                     (Route__HeaderMatcher *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &route__header_matcher__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor route__virtual_host__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__VirtualHost, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "domains",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(Route__VirtualHost, n_domains),
    offsetof(Route__VirtualHost, domains),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "routes",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__VirtualHost, n_routes),
    offsetof(Route__VirtualHost, routes),
    &route__route__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__virtual_host__field_indices_by_name[] = {
  1,   /* field[1] = domains */
  0,   /* field[0] = name */
  2,   /* field[2] = routes */
};
static const ProtobufCIntRange route__virtual_host__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor route__virtual_host__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.VirtualHost",
  "VirtualHost",
  "Route__VirtualHost",
  "route",
  sizeof(Route__VirtualHost),
  3,
  route__virtual_host__field_descriptors,
  route__virtual_host__field_indices_by_name,
  1,  route__virtual_host__number_ranges,
  (ProtobufCMessageInit) route__virtual_host__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__route__field_descriptors[3] =
{
  {
    "match",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Route__Route, match),
    &route__route_match__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "route",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Route__Route, route),
    &route__route_action__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    14,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__Route, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__route__field_indices_by_name[] = {
  0,   /* field[0] = match */
  2,   /* field[2] = name */
  1,   /* field[1] = route */
};
static const ProtobufCIntRange route__route__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 14, 2 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor route__route__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.Route",
  "Route",
  "Route__Route",
  "route",
  sizeof(Route__Route),
  3,
  route__route__field_descriptors,
  route__route__field_indices_by_name,
  2,  route__route__number_ranges,
  (ProtobufCMessageInit) route__route__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__route_match__field_descriptors[3] =
{
  {
    "prefix",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__RouteMatch, prefix),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "case_sensitive",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(Route__RouteMatch, case_sensitive),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "headers",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__RouteMatch, n_headers),
    offsetof(Route__RouteMatch, headers),
    &route__header_matcher__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__route_match__field_indices_by_name[] = {
  1,   /* field[1] = case_sensitive */
  2,   /* field[2] = headers */
  0,   /* field[0] = prefix */
};
static const ProtobufCIntRange route__route_match__number_ranges[3 + 1] =
{
  { 1, 0 },
  { 4, 1 },
  { 6, 2 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor route__route_match__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.RouteMatch",
  "RouteMatch",
  "Route__RouteMatch",
  "route",
  sizeof(Route__RouteMatch),
  3,
  route__route_match__field_descriptors,
  route__route_match__field_indices_by_name,
  3,  route__route_match__number_ranges,
  (ProtobufCMessageInit) route__route_match__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__route_action__hash_policy__header__field_descriptors[1] =
{
  {
    "header_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__RouteAction__HashPolicy__Header, header_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__route_action__hash_policy__header__field_indices_by_name[] = {
  0,   /* field[0] = header_name */
};
static const ProtobufCIntRange route__route_action__hash_policy__header__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor route__route_action__hash_policy__header__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.RouteAction.HashPolicy.Header",
  "Header",
  "Route__RouteAction__HashPolicy__Header",
  "route",
  sizeof(Route__RouteAction__HashPolicy__Header),
  1,
  route__route_action__hash_policy__header__field_descriptors,
  route__route_action__hash_policy__header__field_indices_by_name,
  1,  route__route_action__hash_policy__header__number_ranges,
  (ProtobufCMessageInit) route__route_action__hash_policy__header__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__route_action__hash_policy__field_descriptors[1] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__RouteAction__HashPolicy, policy_specifier_case),
    offsetof(Route__RouteAction__HashPolicy, header),
    &route__route_action__hash_policy__header__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__route_action__hash_policy__field_indices_by_name[] = {
  0,   /* field[0] = header */
};
static const ProtobufCIntRange route__route_action__hash_policy__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor route__route_action__hash_policy__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.RouteAction.HashPolicy",
  "HashPolicy",
  "Route__RouteAction__HashPolicy",
  "route",
  sizeof(Route__RouteAction__HashPolicy),
  1,
  route__route_action__hash_policy__field_descriptors,
  route__route_action__hash_policy__field_indices_by_name,
  1,  route__route_action__hash_policy__number_ranges,
  (ProtobufCMessageInit) route__route_action__hash_policy__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__route_action__field_descriptors[6] =
{
  {
    "cluster",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    offsetof(Route__RouteAction, cluster_specifier_case),
    offsetof(Route__RouteAction, cluster),
    NULL,
    &protobuf_c_empty_string,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "weighted_clusters",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__RouteAction, cluster_specifier_case),
    offsetof(Route__RouteAction, weighted_clusters),
    &route__weighted_cluster__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "prefix_rewrite",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__RouteAction, prefix_rewrite),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "timeout",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Route__RouteAction, timeout),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "retry_policy",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Route__RouteAction, retry_policy),
    &route__retry_policy__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash_policy",
    15,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__RouteAction, n_hash_policy),
    offsetof(Route__RouteAction, hash_policy),
    &route__route_action__hash_policy__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__route_action__field_indices_by_name[] = {
  0,   /* field[0] = cluster */
  5,   /* field[5] = hash_policy */
  2,   /* field[2] = prefix_rewrite */
  4,   /* field[4] = retry_policy */
  3,   /* field[3] = timeout */
  1,   /* field[1] = weighted_clusters */
};
static const ProtobufCIntRange route__route_action__number_ranges[5 + 1] =
{
  { 1, 0 },
  { 3, 1 },
  { 5, 2 },
  { 8, 3 },
  { 15, 5 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor route__route_action__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.RouteAction",
  "RouteAction",
  "Route__RouteAction",
  "route",
  sizeof(Route__RouteAction),
  6,
  route__route_action__field_descriptors,
  route__route_action__field_indices_by_name,
  5,  route__route_action__number_ranges,
  (ProtobufCMessageInit) route__route_action__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__retry_policy__field_descriptors[1] =
{
  {
    "num_retries",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Route__RetryPolicy, num_retries),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__retry_policy__field_indices_by_name[] = {
  0,   /* field[0] = num_retries */
};
static const ProtobufCIntRange route__retry_policy__number_ranges[1 + 1] =
{
  { 2, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor route__retry_policy__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.RetryPolicy",
  "RetryPolicy",
  "Route__RetryPolicy",
  "route",
  sizeof(Route__RetryPolicy),
  1,
  route__retry_policy__field_descriptors,
  route__retry_policy__field_indices_by_name,
  1,  route__retry_policy__number_ranges,
  (ProtobufCMessageInit) route__retry_policy__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__weighted_cluster__field_descriptors[1] =
{
  {
    "clusters",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Route__WeightedCluster, n_clusters),
    offsetof(Route__WeightedCluster, clusters),
    &route__cluster_weight__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__weighted_cluster__field_indices_by_name[] = {
  0,   /* field[0] = clusters */
};
static const ProtobufCIntRange route__weighted_cluster__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor route__weighted_cluster__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.WeightedCluster",
  "WeightedCluster",
  "Route__WeightedCluster",
  "route",
  sizeof(Route__WeightedCluster),
  1,
  route__weighted_cluster__field_descriptors,
  route__weighted_cluster__field_indices_by_name,
  1,  route__weighted_cluster__number_ranges,
  (ProtobufCMessageInit) route__weighted_cluster__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__cluster_weight__field_descriptors[2] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__ClusterWeight, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "weight",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Route__ClusterWeight, weight),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__cluster_weight__field_indices_by_name[] = {
  0,   /* field[0] = name */
  1,   /* field[1] = weight */
};
static const ProtobufCIntRange route__cluster_weight__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor route__cluster_weight__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.ClusterWeight",
  "ClusterWeight",
  "Route__ClusterWeight",
  "route",
  sizeof(Route__ClusterWeight),
  2,
  route__cluster_weight__field_descriptors,
  route__cluster_weight__field_indices_by_name,
  1,  route__cluster_weight__number_ranges,
  (ProtobufCMessageInit) route__cluster_weight__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor route__header_matcher__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Route__HeaderMatcher, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "exact_match",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    offsetof(Route__HeaderMatcher, header_match_specifier_case),
    offsetof(Route__HeaderMatcher, exact_match),
    NULL,
    &protobuf_c_empty_string,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "prefix_match",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    offsetof(Route__HeaderMatcher, header_match_specifier_case),
    offsetof(Route__HeaderMatcher, prefix_match),
    NULL,
    &protobuf_c_empty_string,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned route__header_matcher__field_indices_by_name[] = {
  1,   /* field[1] = exact_match */
  0,   /* field[0] = name */
  2,   /* field[2] = prefix_match */
};
static const ProtobufCIntRange route__header_matcher__number_ranges[3 + 1] =
{
  { 1, 0 },
  { 4, 1 },
  { 9, 2 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor route__header_matcher__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "route.HeaderMatcher",
  "HeaderMatcher",
  "Route__HeaderMatcher",
  "route",
  sizeof(Route__HeaderMatcher),
  3,
  route__header_matcher__field_descriptors,
  route__header_matcher__field_indices_by_name,
  3,  route__header_matcher__number_ranges,
  (ProtobufCMessageInit) route__header_matcher__init,
  NULL,NULL,NULL    /* reserved[123] */
};
