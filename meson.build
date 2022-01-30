
project('gst-aavddec', 'c', version : '0.1.1', license : 'LGPL')

plugins_install_dir = join_paths(get_option('libdir'), 'gstreamer-1.0')

cc = meson.get_compiler('c')

gst_version = meson.project_version()

api_version = '1.0'

gst_dep = dependency('gstreamer-1.0',
    fallback : ['gstreamer', 'gst_dep'])
gstbase_dep = dependency('gstreamer-base-1.0',
    fallback : ['gstreamer', 'gst_base_dep'])
crypto_dep = dependency('openssl')

aavddec_c_args = ['-DHAVE_CONFIG_H']

cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', gst_version)
cdata.set_quoted('PACKAGE', 'gst-aavd-plugin')
cdata.set_quoted('GST_LICENSE', 'LGPL')
cdata.set_quoted('GST_API_VERSION', api_version)
cdata.set_quoted('GST_PACKAGE_NAME', 'GStreamer AAX decryption Plug-in')
cdata.set_quoted('GST_PACKAGE_ORIGIN', 'https://github.com/StefanBruens/gst-aavddec')
configure_file(output : 'config.h', configuration : cdata)

aavddec_sources = [
  'src/gstaavddec.c',
  'src/gstaavddecrypt.c',
  ]

gstaavddec = library('gstaavddec',
  aavddec_sources,
  c_args: aavddec_c_args,
  dependencies : [gst_dep, gstbase_dep, crypto_dep],
  install : true,
  install_dir : plugins_install_dir,
)

