// Code generated by mockery v1.0.0. DO NOT EDIT.

// Generated: please do not edit by hand

package mocks

import do "github.com/digitalocean/doctl/do"
import godo "github.com/digitalocean/godo"
import mock "github.com/stretchr/testify/mock"

// ProjectsService is an autogenerated mock type for the ProjectsService type
type ProjectsService struct {
	mock.Mock
}

// AssignResources provides a mock function with given fields: projectUUID, resources
func (_m *ProjectsService) AssignResources(projectUUID string, resources []string) (do.ProjectResources, error) {
	ret := _m.Called(projectUUID, resources)

	var r0 do.ProjectResources
	if rf, ok := ret.Get(0).(func(string, []string) do.ProjectResources); ok {
		r0 = rf(projectUUID, resources)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.ProjectResources)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, []string) error); ok {
		r1 = rf(projectUUID, resources)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Create provides a mock function with given fields: _a0
func (_m *ProjectsService) Create(_a0 *godo.CreateProjectRequest) (*do.Project, error) {
	ret := _m.Called(_a0)

	var r0 *do.Project
	if rf, ok := ret.Get(0).(func(*godo.CreateProjectRequest) *do.Project); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*do.Project)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*godo.CreateProjectRequest) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: projectUUID
func (_m *ProjectsService) Delete(projectUUID string) error {
	ret := _m.Called(projectUUID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(projectUUID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: projectUUID
func (_m *ProjectsService) Get(projectUUID string) (*do.Project, error) {
	ret := _m.Called(projectUUID)

	var r0 *do.Project
	if rf, ok := ret.Get(0).(func(string) *do.Project); ok {
		r0 = rf(projectUUID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*do.Project)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(projectUUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDefault provides a mock function with given fields:
func (_m *ProjectsService) GetDefault() (*do.Project, error) {
	ret := _m.Called()

	var r0 *do.Project
	if rf, ok := ret.Get(0).(func() *do.Project); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*do.Project)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields:
func (_m *ProjectsService) List() (do.Projects, error) {
	ret := _m.Called()

	var r0 do.Projects
	if rf, ok := ret.Get(0).(func() do.Projects); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.Projects)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListResources provides a mock function with given fields: projectUUID
func (_m *ProjectsService) ListResources(projectUUID string) (do.ProjectResources, error) {
	ret := _m.Called(projectUUID)

	var r0 do.ProjectResources
	if rf, ok := ret.Get(0).(func(string) do.ProjectResources); ok {
		r0 = rf(projectUUID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.ProjectResources)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(projectUUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: projectUUID, req
func (_m *ProjectsService) Update(projectUUID string, req *godo.UpdateProjectRequest) (*do.Project, error) {
	ret := _m.Called(projectUUID, req)

	var r0 *do.Project
	if rf, ok := ret.Get(0).(func(string, *godo.UpdateProjectRequest) *do.Project); ok {
		r0 = rf(projectUUID, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*do.Project)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, *godo.UpdateProjectRequest) error); ok {
		r1 = rf(projectUUID, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}