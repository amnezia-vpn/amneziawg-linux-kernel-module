# SPDX-License-Identifier: GPL-2.0
"""Run the actual CPS parser with ASan/UBSan and deterministic allocation failures."""
import argparse
import os
import pathlib
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = r'''
static void assert_previous(struct jp_spec *s) {
 assert(s->pkt_size==2 && s->mods_size==0);
 assert(!strcmp(s->desc,"<b 0x4142>"));
 assert(!memcmp(s->pkt,"AB",2));
}
int main(int argc, char **argv) {
 struct jp_spec s={0};
 assert(argc==2);
 if(!strcmp(argv[1],"negative")) {
  const char *bad[]={"<r -1>","<rc -1>","<rd -1>","<r -1><b 0x4141>"};
  for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
   assert(jp_spec_setup(&s,bad[i])==-EINVAL);
   assert(!s.desc && !s.pkt_size);
  }
 } else if(!strcmp(argv[1],"rollback")) {
  assert(!jp_spec_setup(&s,"<b 0x4142>"));
  assert(jp_spec_setup(&s,"<unknown>")==-EINVAL);
  assert_previous(&s);
 } else if(!strcmp(argv[1],"bounds")) {
  assert(!jp_spec_setup(&s,"<r 65507>")); assert(s.pkt_size==65507);
  assert(jp_spec_setup(&s,"<r 65508>")<0); assert(s.pkt_size==65507);
  assert(jp_spec_setup(&s,"<r 32754><r 32754>")<0); assert(s.pkt_size==65507);
  assert(!jp_spec_setup(&s,"<b 0x4142><r 2><c><t><rc 2><rd 2>"));
  assert(s.pkt_size==16 && s.mods_size==5 && !memcmp(s.pkt,"AB",2));
  assert(!jp_spec_setup(&s,"")); assert(!s.pkt_size && !strcmp(s.desc,""));
 } else if(!strcmp(argv[1],"oom")) {
  unsigned failures=0;
  for(int point=1;point<20;point++) {
   allocations=fail_at=0;
   assert(!jp_spec_setup(&s,"<b 0x4142>"));
   allocations=0; fail_at=point;
   int rc=jp_spec_setup(&s,"<b 0x43><r 2>");
   fail_at=0;
   if(rc==-ENOMEM) { assert_previous(&s); failures++; }
   else assert(rc==0);
   jp_spec_free(&s);
  }
  assert(failures>=6);
 } else return 2;
 jp_spec_free(&s); puts("PASS"); return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=pathlib.Path, default=ROOT / 'src')
    parser.add_argument('--case', choices=['negative', 'rollback', 'bounds', 'oom'])
    args = parser.parse_args()
    def strip(text):
        return '\n'.join(l for l in text.splitlines() if not l.startswith('#include'))
    source = ((ROOT / 'tests/cps-shim.h').read_text() + '\n' +
              strip((args.source / 'junk.h').read_text()) + '\n' +
              strip((args.source / 'junk.c').read_text()) + '\n' + MAIN)
    with tempfile.TemporaryDirectory(prefix='awg-cps-') as directory:
        work = pathlib.Path(directory)
        (work / 'test.c').write_text(source)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            str(work / 'test.c'), '-o', str(work / 'test')], check=True)
        for case in [args.case] if args.case else ['negative', 'rollback', 'bounds', 'oom']:
            subprocess.run([str(work / 'test'), case], check=True)
            print('PASS: CPS ' + case, flush=True)


if __name__ == '__main__':
    main()
