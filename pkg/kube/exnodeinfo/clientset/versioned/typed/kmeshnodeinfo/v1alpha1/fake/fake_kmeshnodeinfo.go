/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	context "context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
)

// FakeKmeshNodeInfos implements KmeshNodeInfoInterface
type FakeKmeshNodeInfos struct {
	Fake *FakeKmeshnodeinfoV1alpha1
	ns   string
}

var kmeshnodeinfosResource = v1alpha1.SchemeGroupVersion.WithResource("kmeshnodeinfos")

var kmeshnodeinfosKind = v1alpha1.SchemeGroupVersion.WithKind("KmeshNodeInfo")

// Get takes name of the kmeshNodeInfo, and returns the corresponding kmeshNodeInfo object, and an error if there is any.
func (c *FakeKmeshNodeInfos) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.KmeshNodeInfo, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfo{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(kmeshnodeinfosResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.KmeshNodeInfo), err
}

// List takes label and field selectors, and returns the list of KmeshNodeInfos that match those selectors.
func (c *FakeKmeshNodeInfos) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.KmeshNodeInfoList, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfoList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(kmeshnodeinfosResource, kmeshnodeinfosKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.KmeshNodeInfoList{ListMeta: obj.(*v1alpha1.KmeshNodeInfoList).ListMeta}
	for _, item := range obj.(*v1alpha1.KmeshNodeInfoList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested kmeshNodeInfos.
func (c *FakeKmeshNodeInfos) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(kmeshnodeinfosResource, c.ns, opts))

}

// Create takes the representation of a kmeshNodeInfo and creates it.  Returns the server's representation of the kmeshNodeInfo, and an error, if there is any.
func (c *FakeKmeshNodeInfos) Create(ctx context.Context, kmeshNodeInfo *v1alpha1.KmeshNodeInfo, opts v1.CreateOptions) (result *v1alpha1.KmeshNodeInfo, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfo{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(kmeshnodeinfosResource, c.ns, kmeshNodeInfo, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.KmeshNodeInfo), err
}

// Update takes the representation of a kmeshNodeInfo and updates it. Returns the server's representation of the kmeshNodeInfo, and an error, if there is any.
func (c *FakeKmeshNodeInfos) Update(ctx context.Context, kmeshNodeInfo *v1alpha1.KmeshNodeInfo, opts v1.UpdateOptions) (result *v1alpha1.KmeshNodeInfo, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfo{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(kmeshnodeinfosResource, c.ns, kmeshNodeInfo, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.KmeshNodeInfo), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeKmeshNodeInfos) UpdateStatus(ctx context.Context, kmeshNodeInfo *v1alpha1.KmeshNodeInfo, opts v1.UpdateOptions) (result *v1alpha1.KmeshNodeInfo, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfo{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(kmeshnodeinfosResource, "status", c.ns, kmeshNodeInfo, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.KmeshNodeInfo), err
}

// Delete takes name of the kmeshNodeInfo and deletes it. Returns an error if one occurs.
func (c *FakeKmeshNodeInfos) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(kmeshnodeinfosResource, c.ns, name, opts), &v1alpha1.KmeshNodeInfo{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeKmeshNodeInfos) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(kmeshnodeinfosResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.KmeshNodeInfoList{})
	return err
}

// Patch applies the patch and returns the patched kmeshNodeInfo.
func (c *FakeKmeshNodeInfos) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.KmeshNodeInfo, err error) {
	emptyResult := &v1alpha1.KmeshNodeInfo{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(kmeshnodeinfosResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.KmeshNodeInfo), err
}
