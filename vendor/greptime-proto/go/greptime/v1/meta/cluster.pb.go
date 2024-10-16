// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.6
// source: greptime/v1/meta/cluster.proto

package meta

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_greptime_v1_meta_cluster_proto protoreflect.FileDescriptor

var file_greptime_v1_meta_cluster_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x67, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65,
	0x74, 0x61, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x10, 0x67, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x6d, 0x65,
	0x74, 0x61, 0x1a, 0x1c, 0x67, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2f, 0x76, 0x31, 0x2f,
	0x6d, 0x65, 0x74, 0x61, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x32, 0xa6, 0x01, 0x0a, 0x07, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x51, 0x0a, 0x08,
	0x42, 0x61, 0x74, 0x63, 0x68, 0x47, 0x65, 0x74, 0x12, 0x21, 0x2e, 0x67, 0x72, 0x65, 0x70, 0x74,
	0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x2e, 0x42, 0x61, 0x74, 0x63,
	0x68, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x67, 0x72,
	0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x2e, 0x42,
	0x61, 0x74, 0x63, 0x68, 0x47, 0x65, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x48, 0x0a, 0x05, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x1e, 0x2e, 0x67, 0x72, 0x65, 0x70, 0x74,
	0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x2e, 0x52, 0x61, 0x6e, 0x67,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x67, 0x72, 0x65, 0x70, 0x74,
	0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x2e, 0x52, 0x61, 0x6e, 0x67,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65,
	0x54, 0x65, 0x61, 0x6d, 0x2f, 0x67, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2d, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x67, 0x72, 0x65, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x2f,
	0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_greptime_v1_meta_cluster_proto_goTypes = []interface{}{
	(*BatchGetRequest)(nil),  // 0: greptime.v1.meta.BatchGetRequest
	(*RangeRequest)(nil),     // 1: greptime.v1.meta.RangeRequest
	(*BatchGetResponse)(nil), // 2: greptime.v1.meta.BatchGetResponse
	(*RangeResponse)(nil),    // 3: greptime.v1.meta.RangeResponse
}
var file_greptime_v1_meta_cluster_proto_depIdxs = []int32{
	0, // 0: greptime.v1.meta.Cluster.BatchGet:input_type -> greptime.v1.meta.BatchGetRequest
	1, // 1: greptime.v1.meta.Cluster.Range:input_type -> greptime.v1.meta.RangeRequest
	2, // 2: greptime.v1.meta.Cluster.BatchGet:output_type -> greptime.v1.meta.BatchGetResponse
	3, // 3: greptime.v1.meta.Cluster.Range:output_type -> greptime.v1.meta.RangeResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_greptime_v1_meta_cluster_proto_init() }
func file_greptime_v1_meta_cluster_proto_init() {
	if File_greptime_v1_meta_cluster_proto != nil {
		return
	}
	file_greptime_v1_meta_store_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_greptime_v1_meta_cluster_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_greptime_v1_meta_cluster_proto_goTypes,
		DependencyIndexes: file_greptime_v1_meta_cluster_proto_depIdxs,
	}.Build()
	File_greptime_v1_meta_cluster_proto = out.File
	file_greptime_v1_meta_cluster_proto_rawDesc = nil
	file_greptime_v1_meta_cluster_proto_goTypes = nil
	file_greptime_v1_meta_cluster_proto_depIdxs = nil
}