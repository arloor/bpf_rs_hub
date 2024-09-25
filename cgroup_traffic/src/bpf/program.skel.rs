// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::absolute_paths)]
#[allow(clippy::transmute_ptr_to_ref)]
#[allow(clippy::upper_case_acronyms)]
#[warn(single_use_lifetimes)]
mod imp {
    #[allow(unused_imports)]
    use super::*;
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;

    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder
            .name("program_bpf")
            .map("process_traffic", false)
            .prog("count_egress_packets")
            .prog("count_ingress_packets");

        builder.build()
    }

    #[derive(Default)]
    pub struct ProgramSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'a> SkelBuilder<'a> for ProgramSkelBuilder {
        type Output = OpenProgramSkel<'a>;
        fn open(self) -> libbpf_rs::Result<OpenProgramSkel<'a>> {
            let opts = *self.obj_builder.opts();
            self.open_opts(opts)
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
        ) -> libbpf_rs::Result<OpenProgramSkel<'a>> {
            let mut skel_config = build_skel_config()?;

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            #[allow(unused_mut)]
            let mut skel = OpenProgramSkel {
                obj,
                // SAFETY: Our `struct_ops` type contains only pointers,
                //         which are allowed to be NULL.
                // TODO: Generate and use a `Default` representation
                //       instead, to cut down on unsafe code.
                struct_ops: unsafe { std::mem::zeroed() },
                skel_config,
            };

            Ok(skel)
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    pub struct OpenProgramMapsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenProgramMapsMut<'_> {
        pub fn process_traffic(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("process_traffic").unwrap()
        }
    }

    pub struct OpenProgramMaps<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenProgramMaps<'_> {
        pub fn process_traffic(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("process_traffic").unwrap()
        }
    }

    pub struct OpenProgramProgs<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenProgramProgs<'_> {
        pub fn count_egress_packets(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("count_egress_packets").unwrap()
        }

        pub fn count_ingress_packets(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("count_ingress_packets").unwrap()
        }
    }

    pub struct OpenProgramProgsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenProgramProgsMut<'_> {
        pub fn count_egress_packets(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("count_egress_packets").unwrap()
        }

        pub fn count_ingress_packets(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("count_ingress_packets").unwrap()
        }
    }

    pub mod program_types {
        #[allow(unused_imports)]
        use super::*;

        #[derive(Debug, Clone)]
        #[repr(C)]
        pub struct struct_ops {}

        impl struct_ops {}
    }

    pub struct OpenProgramSkel<'a> {
        pub obj: libbpf_rs::OpenObject,
        pub struct_ops: program_types::struct_ops,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
    }

    impl<'a> OpenSkel for OpenProgramSkel<'a> {
        type Output = ProgramSkel<'a>;
        fn load(mut self) -> libbpf_rs::Result<ProgramSkel<'a>> {
            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

            Ok(ProgramSkel {
                obj,
                struct_ops: self.struct_ops,
                skel_config: self.skel_config,
                links: ProgramLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            &self.obj
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            &mut self.obj
        }
    }
    impl OpenProgramSkel<'_> {
        pub fn progs_mut(&mut self) -> OpenProgramProgsMut<'_> {
            OpenProgramProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn progs(&self) -> OpenProgramProgs<'_> {
            OpenProgramProgs { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> OpenProgramMapsMut<'_> {
            OpenProgramMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> OpenProgramMaps<'_> {
            OpenProgramMaps { inner: &self.obj }
        }
    }

    pub struct ProgramMapsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl ProgramMapsMut<'_> {
        pub fn process_traffic(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("process_traffic").unwrap()
        }
    }

    pub struct ProgramMaps<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl ProgramMaps<'_> {
        pub fn process_traffic(&self) -> &libbpf_rs::Map {
            self.inner.map("process_traffic").unwrap()
        }
    }

    pub struct ProgramProgs<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl ProgramProgs<'_> {
        pub fn count_egress_packets(&self) -> &libbpf_rs::Program {
            self.inner.prog("count_egress_packets").unwrap()
        }

        pub fn count_ingress_packets(&self) -> &libbpf_rs::Program {
            self.inner.prog("count_ingress_packets").unwrap()
        }
    }

    pub struct ProgramProgsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl ProgramProgsMut<'_> {
        pub fn count_egress_packets(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("count_egress_packets").unwrap()
        }

        pub fn count_ingress_packets(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("count_ingress_packets").unwrap()
        }
    }

    #[derive(Default)]
    pub struct ProgramLinks {
        pub count_egress_packets: Option<libbpf_rs::Link>,
        pub count_ingress_packets: Option<libbpf_rs::Link>,
    }

    pub struct ProgramSkel<'a> {
        pub obj: libbpf_rs::Object,
        struct_ops: program_types::struct_ops,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        pub links: ProgramLinks,
    }

    unsafe impl Send for ProgramSkel<'_> {}
    unsafe impl Sync for ProgramSkel<'_> {}

    impl Skel for ProgramSkel<'_> {
        fn object(&self) -> &libbpf_rs::Object {
            &self.obj
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            &mut self.obj
        }

        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            self.links = ProgramLinks {
                count_egress_packets: core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                    .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }),
                count_ingress_packets: core::ptr::NonNull::new(self.skel_config.prog_link_ptr(1)?)
                    .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }),
            };

            Ok(())
        }
    }
    impl ProgramSkel<'_> {
        pub fn progs_mut(&mut self) -> ProgramProgsMut<'_> {
            ProgramProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn progs(&self) -> ProgramProgs<'_> {
            ProgramProgs { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> ProgramMapsMut<'_> {
            ProgramMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> ProgramMaps<'_> {
            ProgramMaps { inner: &self.obj }
        }

        pub fn struct_ops_raw(&self) -> *const program_types::struct_ops {
            &self.struct_ops
        }

        pub fn struct_ops(&self) -> &program_types::struct_ops {
            &self.struct_ops
        }
    }

    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 11, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 99, 103, 114, 111, 117, 112, 95, 115, 107, 98, 47, 101, 103, 114, 101, 115, 115, 0,
        99, 103, 114, 111, 117, 112, 95, 115, 107, 98, 47, 105, 110, 103, 114, 101, 115, 115, 0,
        108, 105, 99, 101, 110, 115, 101, 0, 46, 109, 97, 112, 115, 0, 112, 114, 111, 103, 114, 97,
        109, 46, 98, 112, 102, 46, 99, 0, 76, 66, 66, 48, 95, 50, 0, 76, 66, 66, 49, 95, 50, 0, 99,
        111, 117, 110, 116, 95, 101, 103, 114, 101, 115, 115, 95, 112, 97, 99, 107, 101, 116, 115,
        0, 112, 114, 111, 99, 101, 115, 115, 95, 116, 114, 97, 102, 102, 105, 99, 0, 99, 111, 117,
        110, 116, 95, 105, 110, 103, 114, 101, 115, 115, 95, 112, 97, 99, 107, 101, 116, 115, 0,
        95, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 101, 108, 99, 103, 114, 111, 117,
        112, 95, 115, 107, 98, 47, 101, 103, 114, 101, 115, 115, 0, 46, 114, 101, 108, 99, 103,
        114, 111, 117, 112, 95, 115, 107, 98, 47, 105, 110, 103, 114, 101, 115, 115, 0, 46, 66, 84,
        70, 0, 46, 66, 84, 70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 0,
        0, 0, 0, 0, 3, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 4, 0, 88, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0,
        0, 0, 0, 0, 0, 117, 0, 0, 0, 17, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
        133, 0, 0, 0, 18, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 155, 0, 0, 0,
        17, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 191, 22, 0, 0, 0, 0, 0, 0,
        183, 1, 0, 0, 0, 0, 0, 0, 99, 26, 252, 255, 0, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0, 7, 2,
        0, 0, 252, 255, 255, 255, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 1,
        0, 0, 0, 21, 0, 2, 0, 0, 0, 0, 0, 97, 97, 0, 0, 0, 0, 0, 0, 219, 16, 0, 0, 0, 0, 0, 0, 183,
        0, 0, 0, 1, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 191, 22, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 1,
        0, 0, 0, 99, 26, 252, 255, 0, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 252, 255,
        255, 255, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 1, 0, 0, 0, 21, 0,
        2, 0, 0, 0, 0, 0, 97, 97, 0, 0, 0, 0, 0, 0, 219, 16, 0, 0, 0, 0, 0, 0, 183, 0, 0, 0, 1, 0,
        0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 68, 117, 97, 108, 32, 77, 73, 84, 47, 71, 80, 76, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 7, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 232, 3, 0, 0, 185, 3,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 0, 0,
        0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 8,
        7, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 8, 8, 0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 10, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 8, 11, 0, 0, 0, 52, 0,
        0, 0, 0, 0, 0, 8, 12, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0,
        0, 4, 0, 0, 4, 32, 0, 0, 0, 77, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 82, 0, 0, 0, 5, 0, 0, 0,
        64, 0, 0, 0, 86, 0, 0, 0, 9, 0, 0, 0, 128, 0, 0, 0, 92, 0, 0, 0, 1, 0, 0, 0, 192, 0, 0, 0,
        104, 0, 0, 0, 0, 0, 0, 14, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 16, 0, 0, 0,
        120, 0, 0, 0, 34, 0, 0, 4, 192, 0, 0, 0, 130, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 134, 0, 0,
        0, 7, 0, 0, 0, 32, 0, 0, 0, 143, 0, 0, 0, 7, 0, 0, 0, 64, 0, 0, 0, 148, 0, 0, 0, 7, 0, 0,
        0, 96, 0, 0, 0, 162, 0, 0, 0, 7, 0, 0, 0, 128, 0, 0, 0, 171, 0, 0, 0, 7, 0, 0, 0, 160, 0,
        0, 0, 184, 0, 0, 0, 7, 0, 0, 0, 192, 0, 0, 0, 193, 0, 0, 0, 7, 0, 0, 0, 224, 0, 0, 0, 204,
        0, 0, 0, 7, 0, 0, 0, 0, 1, 0, 0, 213, 0, 0, 0, 7, 0, 0, 0, 32, 1, 0, 0, 229, 0, 0, 0, 7, 0,
        0, 0, 64, 1, 0, 0, 237, 0, 0, 0, 7, 0, 0, 0, 96, 1, 0, 0, 246, 0, 0, 0, 17, 0, 0, 0, 128,
        1, 0, 0, 249, 0, 0, 0, 7, 0, 0, 0, 32, 2, 0, 0, 254, 0, 0, 0, 7, 0, 0, 0, 64, 2, 0, 0, 9,
        1, 0, 0, 7, 0, 0, 0, 96, 2, 0, 0, 14, 1, 0, 0, 7, 0, 0, 0, 128, 2, 0, 0, 23, 1, 0, 0, 7, 0,
        0, 0, 160, 2, 0, 0, 31, 1, 0, 0, 7, 0, 0, 0, 192, 2, 0, 0, 38, 1, 0, 0, 7, 0, 0, 0, 224, 2,
        0, 0, 49, 1, 0, 0, 7, 0, 0, 0, 0, 3, 0, 0, 59, 1, 0, 0, 18, 0, 0, 0, 32, 3, 0, 0, 70, 1, 0,
        0, 18, 0, 0, 0, 160, 3, 0, 0, 80, 1, 0, 0, 7, 0, 0, 0, 32, 4, 0, 0, 92, 1, 0, 0, 7, 0, 0,
        0, 64, 4, 0, 0, 103, 1, 0, 0, 7, 0, 0, 0, 96, 4, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 128, 4, 0,
        0, 113, 1, 0, 0, 11, 0, 0, 0, 192, 4, 0, 0, 120, 1, 0, 0, 7, 0, 0, 0, 0, 5, 0, 0, 129, 1,
        0, 0, 7, 0, 0, 0, 32, 5, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 64, 5, 0, 0, 138, 1, 0, 0, 7, 0, 0,
        0, 128, 5, 0, 0, 147, 1, 0, 0, 23, 0, 0, 0, 160, 5, 0, 0, 159, 1, 0, 0, 11, 0, 0, 0, 192,
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 7, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 3, 0, 0, 0, 0, 7, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 5, 8,
        0, 0, 0, 168, 1, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 32, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 5, 8, 0, 0, 0, 178, 1, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 31, 0, 0, 0, 181, 1, 0, 0, 0, 0, 0, 8, 24, 0, 0, 0, 186, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0,
        0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 2, 0, 0, 0, 200, 1, 0, 0, 15, 0, 0, 0, 204, 1, 0,
        0, 1, 0, 0, 12, 25, 0, 0, 0, 225, 1, 0, 0, 1, 0, 0, 12, 25, 0, 0, 0, 247, 1, 0, 0, 0, 0, 0,
        1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 28, 0, 0, 0, 4, 0, 0, 0, 13,
        0, 0, 0, 252, 1, 0, 0, 0, 0, 0, 14, 29, 0, 0, 0, 1, 0, 0, 0, 6, 2, 0, 0, 0, 0, 0, 7, 0, 0,
        0, 0, 15, 2, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 134, 3, 0, 0, 1, 0, 0, 15, 13, 0, 0, 0, 30, 0,
        0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 142, 3, 0, 0, 1, 0, 0, 15, 32, 0, 0, 0, 14, 0, 0, 0, 0, 0,
        0, 0, 32, 0, 0, 0, 0, 105, 110, 116, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95,
        84, 89, 80, 69, 95, 95, 0, 117, 51, 50, 0, 95, 95, 117, 51, 50, 0, 117, 110, 115, 105, 103,
        110, 101, 100, 32, 105, 110, 116, 0, 117, 54, 52, 0, 95, 95, 117, 54, 52, 0, 117, 110, 115,
        105, 103, 110, 101, 100, 32, 108, 111, 110, 103, 32, 108, 111, 110, 103, 0, 116, 121, 112,
        101, 0, 107, 101, 121, 0, 118, 97, 108, 117, 101, 0, 109, 97, 120, 95, 101, 110, 116, 114,
        105, 101, 115, 0, 112, 114, 111, 99, 101, 115, 115, 95, 116, 114, 97, 102, 102, 105, 99, 0,
        95, 95, 115, 107, 95, 98, 117, 102, 102, 0, 108, 101, 110, 0, 112, 107, 116, 95, 116, 121,
        112, 101, 0, 109, 97, 114, 107, 0, 113, 117, 101, 117, 101, 95, 109, 97, 112, 112, 105,
        110, 103, 0, 112, 114, 111, 116, 111, 99, 111, 108, 0, 118, 108, 97, 110, 95, 112, 114,
        101, 115, 101, 110, 116, 0, 118, 108, 97, 110, 95, 116, 99, 105, 0, 118, 108, 97, 110, 95,
        112, 114, 111, 116, 111, 0, 112, 114, 105, 111, 114, 105, 116, 121, 0, 105, 110, 103, 114,
        101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 105, 102, 105, 110, 100, 101, 120,
        0, 116, 99, 95, 105, 110, 100, 101, 120, 0, 99, 98, 0, 104, 97, 115, 104, 0, 116, 99, 95,
        99, 108, 97, 115, 115, 105, 100, 0, 100, 97, 116, 97, 0, 100, 97, 116, 97, 95, 101, 110,
        100, 0, 110, 97, 112, 105, 95, 105, 100, 0, 102, 97, 109, 105, 108, 121, 0, 114, 101, 109,
        111, 116, 101, 95, 105, 112, 52, 0, 108, 111, 99, 97, 108, 95, 105, 112, 52, 0, 114, 101,
        109, 111, 116, 101, 95, 105, 112, 54, 0, 108, 111, 99, 97, 108, 95, 105, 112, 54, 0, 114,
        101, 109, 111, 116, 101, 95, 112, 111, 114, 116, 0, 108, 111, 99, 97, 108, 95, 112, 111,
        114, 116, 0, 100, 97, 116, 97, 95, 109, 101, 116, 97, 0, 116, 115, 116, 97, 109, 112, 0,
        119, 105, 114, 101, 95, 108, 101, 110, 0, 103, 115, 111, 95, 115, 101, 103, 115, 0, 103,
        115, 111, 95, 115, 105, 122, 101, 0, 116, 115, 116, 97, 109, 112, 95, 116, 121, 112, 101,
        0, 104, 119, 116, 115, 116, 97, 109, 112, 0, 102, 108, 111, 119, 95, 107, 101, 121, 115, 0,
        115, 107, 0, 95, 95, 117, 56, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 99, 104, 97,
        114, 0, 115, 107, 98, 0, 99, 111, 117, 110, 116, 95, 101, 103, 114, 101, 115, 115, 95, 112,
        97, 99, 107, 101, 116, 115, 0, 99, 111, 117, 110, 116, 95, 105, 110, 103, 114, 101, 115,
        115, 95, 112, 97, 99, 107, 101, 116, 115, 0, 99, 104, 97, 114, 0, 95, 95, 108, 105, 99,
        101, 110, 115, 101, 0, 98, 112, 102, 95, 115, 111, 99, 107, 0, 98, 112, 102, 95, 102, 108,
        111, 119, 95, 107, 101, 121, 115, 0, 47, 114, 101, 112, 111, 47, 98, 112, 102, 95, 114,
        115, 95, 104, 117, 98, 47, 99, 103, 114, 111, 117, 112, 95, 116, 114, 97, 102, 102, 105,
        99, 47, 115, 114, 99, 47, 98, 112, 102, 47, 112, 114, 111, 103, 114, 97, 109, 46, 98, 112,
        102, 46, 99, 0, 105, 110, 116, 32, 99, 111, 117, 110, 116, 95, 101, 103, 114, 101, 115,
        115, 95, 112, 97, 99, 107, 101, 116, 115, 40, 115, 116, 114, 117, 99, 116, 32, 95, 95, 115,
        107, 95, 98, 117, 102, 102, 32, 42, 115, 107, 98, 41, 0, 32, 32, 32, 32, 95, 95, 117, 51,
        50, 32, 107, 101, 121, 32, 61, 32, 48, 59, 32, 47, 47, 32, 101, 103, 114, 101, 115, 115,
        32, 61, 32, 48, 0, 32, 32, 32, 32, 108, 111, 110, 103, 32, 42, 118, 97, 108, 117, 101, 32,
        61, 32, 98, 112, 102, 95, 109, 97, 112, 95, 108, 111, 111, 107, 117, 112, 95, 101, 108,
        101, 109, 40, 38, 112, 114, 111, 99, 101, 115, 115, 95, 116, 114, 97, 102, 102, 105, 99,
        44, 32, 38, 107, 101, 121, 41, 59, 0, 32, 32, 32, 32, 105, 102, 32, 40, 118, 97, 108, 117,
        101, 41, 0, 32, 32, 32, 32, 32, 32, 32, 32, 95, 95, 115, 121, 110, 99, 95, 102, 101, 116,
        99, 104, 95, 97, 110, 100, 95, 97, 100, 100, 40, 118, 97, 108, 117, 101, 44, 32, 115, 107,
        98, 45, 62, 108, 101, 110, 41, 59, 0, 32, 32, 32, 32, 114, 101, 116, 117, 114, 110, 32, 49,
        59, 0, 105, 110, 116, 32, 99, 111, 117, 110, 116, 95, 105, 110, 103, 114, 101, 115, 115,
        95, 112, 97, 99, 107, 101, 116, 115, 40, 115, 116, 114, 117, 99, 116, 32, 95, 95, 115, 107,
        95, 98, 117, 102, 102, 32, 42, 115, 107, 98, 41, 0, 32, 32, 32, 32, 95, 95, 117, 51, 50,
        32, 107, 101, 121, 32, 61, 32, 49, 59, 32, 47, 47, 32, 105, 110, 103, 114, 101, 115, 115,
        32, 61, 32, 49, 0, 48, 58, 48, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 109, 97, 112,
        115, 0, 99, 103, 114, 111, 117, 112, 95, 115, 107, 98, 47, 101, 103, 114, 101, 115, 115, 0,
        99, 103, 114, 111, 117, 112, 95, 115, 107, 98, 47, 105, 110, 103, 114, 101, 115, 115, 0, 0,
        0, 0, 0, 0, 0, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 36, 0, 0, 0, 20, 1,
        0, 0, 56, 1, 0, 0, 52, 0, 0, 0, 8, 0, 0, 0, 148, 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0,
        0, 166, 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 16, 0, 0, 0, 148, 3, 0, 0, 8, 0, 0,
        0, 0, 0, 0, 0, 29, 2, 0, 0, 83, 2, 0, 0, 0, 60, 0, 0, 16, 0, 0, 0, 29, 2, 0, 0, 131, 2, 0,
        0, 11, 68, 0, 0, 32, 0, 0, 0, 29, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 29, 2, 0,
        0, 164, 2, 0, 0, 19, 76, 0, 0, 64, 0, 0, 0, 29, 2, 0, 0, 227, 2, 0, 0, 9, 80, 0, 0, 72, 0,
        0, 0, 29, 2, 0, 0, 242, 2, 0, 0, 42, 88, 0, 0, 80, 0, 0, 0, 29, 2, 0, 0, 242, 2, 0, 0, 9,
        88, 0, 0, 88, 0, 0, 0, 29, 2, 0, 0, 33, 3, 0, 0, 5, 100, 0, 0, 166, 3, 0, 0, 8, 0, 0, 0, 0,
        0, 0, 0, 29, 2, 0, 0, 47, 3, 0, 0, 0, 116, 0, 0, 16, 0, 0, 0, 29, 2, 0, 0, 96, 3, 0, 0, 11,
        124, 0, 0, 32, 0, 0, 0, 29, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 29, 2, 0, 0, 164,
        2, 0, 0, 19, 132, 0, 0, 64, 0, 0, 0, 29, 2, 0, 0, 227, 2, 0, 0, 9, 136, 0, 0, 72, 0, 0, 0,
        29, 2, 0, 0, 242, 2, 0, 0, 42, 144, 0, 0, 80, 0, 0, 0, 29, 2, 0, 0, 242, 2, 0, 0, 9, 144,
        0, 0, 88, 0, 0, 0, 29, 2, 0, 0, 33, 3, 0, 0, 5, 156, 0, 0, 16, 0, 0, 0, 148, 3, 0, 0, 1, 0,
        0, 0, 72, 0, 0, 0, 16, 0, 0, 0, 130, 3, 0, 0, 0, 0, 0, 0, 166, 3, 0, 0, 1, 0, 0, 0, 72, 0,
        0, 0, 16, 0, 0, 0, 130, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0,
        0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 224, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0,
        240, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0,
        0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 2, 0,
        0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 35, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 120, 2, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 224, 2, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 2, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 0, 0, 0, 9, 0, 0, 0,
        64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 3, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0,
        0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 187, 0,
        0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 3, 0, 0, 0, 0, 0, 0,
        16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0,
        0, 0, 210, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 3, 0,
        0, 0, 0, 0, 0, 185, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 215, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 240, 10, 0, 0, 0, 0, 0, 0, 140, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
