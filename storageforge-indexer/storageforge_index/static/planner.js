'use strict';
const MiB=2**20, GiB=2**30, TiB=2**40;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Designs come from scans (whatever a host prints) and from users. Text never carries control characters (they end a
// comment or a line in a generated script) or < > " ` (they end HTML text or a quoted attribute), so no template can be
// broken out of, escaped or not. Identifiers are held to what their tools accept, so they are safe as script words.
const UNSAFE=/[\u0000-\u001f\u007f<>"`]/g;
function scrub(v){ if(typeof v==='string') return v.replace(UNSAFE,''); if(Array.isArray(v)) return v.map(scrub);
  if(v&&typeof v==='object'){ const o={}; for(const k of Object.keys(v)) o[k]=scrub(v[k]); return o } return v }
const ident=v=>v==null?v:String(v).replace(/[^A-Za-z0-9._@+:-]/g,'_');
const identPath=v=>v==null?v:String(v).replace(/[^A-Za-z0-9._@+:\/-]/g,'_');   // dataset and subvolume names nest with /
const fstabEsc=v=>String(v).replace(/[ \t\\]/g,c=>'\\'+c.charCodeAt(0).toString(8).padStart(3,'0'));   // fstab(5) octal escapes
function tidy(s){
  s.host=String(s.host||'host');
  (s.disks||[]).forEach(d=>{ d.dev=ident(d.dev); if(d.member) d.member=ident(d.member); if(d.tier!=null) d.tier=ident(d.tier);
    (d.parts||[]).forEach(p=>{ p.id=ident(p.id); p.fs=ident(p.fs); if(p.member) p.member=ident(p.member);
      (p.subvols||[]).forEach(v=>{ v.name=identPath(v.name) }) }) });
  (s.pools||[]).forEach(p=>{ ['name','type','level','fs','vg','lv','encryption','tier'].forEach(k=>{ if(p[k]!=null) p[k]=ident(p[k]) });
    p.ashift=parseInt(p.ashift,10)||12;
    (p.datasets||[]).forEach(ds=>{ ds.name=identPath(ds.name); ['fs','recordsize','compression','sync'].forEach(k=>{ if(ds[k]!=null) ds[k]=ident(ds[k]) }) }) });
  (s.links||[]).forEach(l=>{ if(l.kind!=null) l.kind=ident(l.kind) });
  return s;
}
const sum=a=>a.reduce((x,y)=>x+y,0);
function fmtBin(b,d=2){const u=['B','KiB','MiB','GiB','TiB','PiB'];let i=0;while(Math.abs(b)>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(i<2?0:d)+' '+u[i]}
function fmtDec(b,d=2){const u=['B','KB','MB','GB','TB','PB'];let i=0;while(Math.abs(b)>=1000&&i<u.length-1){b/=1000;i++}return b.toFixed(i<2?0:d)+' '+u[i]}
const both=b=>`${fmtDec(b)} · ${fmtBin(b)}`;
function hash(s){let h=2166136261>>>0;for(const c of s){h^=c.charCodeAt(0);h=Math.imul(h,16777619)>>>0}return h}
function fakeUUID(s){let o='',h=hash(s);for(let i=0;i<32;i++){h=Math.imul(h^(h>>>15),2246822507)>>>0;h^=h>>>13;o+=(h&15).toString(16)}return `${o.slice(0,8)}-${o.slice(8,12)}-4${o.slice(13,16)}-a${o.slice(17,20)}-${o.slice(20,32)}`}
const shortUUID=s=>{const u=fakeUUID(s).replace(/-/g,'').toUpperCase();return u.slice(0,4)+'-'+u.slice(4,8)};
const today=()=>new Date().toISOString().slice(0,10);
const daysSince=d=>d?Math.floor((Date.now()-new Date(d+'T00:00:00Z').getTime())/864e5):Infinity;

/* ───────────── example blueprint ───────────── */
function sample(){
  const exos=['a','b','c','d','e','f'].map((x,i)=>({dev:'sd'+x,model:'Seagate Exos X20 ST20000NM002D',serial:'ZVT0'+(4410+i*7)+'K',bus:'SAS 12Gb/s',media:'hdd',size:20000588955648,lbs:512,pbs:4096,table:'gpt',tier:'mass',member:'tank',parts:[]}));
  const s={
    host:'atlas', idMode:'UUID',
    disks:[
      {dev:'nvme0n1',model:'Samsung SSD 990 PRO 2TB',serial:'S6Z2NJ0W412345A',bus:'NVMe PCIe Gen4 x4',media:'ssd',size:2000398934016,lbs:512,pbs:4096,table:'gpt',tier:'fast',os:true,parts:[
        {id:'nvme0n1p1',num:1,start:MiB,size:GiB,fs:'vfat',label:'EFI',mount:'/boot/efi',opts:['umask=0077','nofail']},
        {id:'nvme0n1p2',num:2,start:MiB+GiB,size:'rest',fs:'btrfs',label:'atlas-root',opts:['noatime','compress=zstd:3','discard=async','space_cache=v2','ssd'],
          subvols:[{name:'@',mount:'/'},{name:'@home',mount:'/home'},{name:'@var_log',mount:'/var/log'},{name:'@snapshots',mount:'/.snapshots'}]}]},
      {dev:'nvme1n1',model:'WD_BLACK SN850X 4000GB',serial:'23174M800123',bus:'NVMe PCIe Gen4 x4',media:'ssd',size:4000787030016,lbs:512,pbs:4096,table:'gpt',tier:'fast',parts:[
        {id:'nvme1n1p1',num:1,start:MiB,size:3*TiB,fs:'xfs',label:'scratch',mount:'/mnt/fast_scratch',opts:['noatime','inode64','logbsize=256k','nofail']},
        {id:'nvme1n1p2',num:2,start:MiB+3*TiB,size:400*GiB,fs:'f2fs',label:'burst',mount:'/mnt/burst',opts:['noatime','lazytime','compress_algorithm=zstd','atgc','gc_merge','nofail']},
        {id:'nvme1n1p3',num:3,start:MiB+3*TiB+400*GiB,size:'rest',fs:'zfs_member',label:'tank-l2arc',member:'tank',role:'cache'}]},
      {dev:'nvme2n1',model:'INTEL SSDPEK1A118GA (Optane P1600X)',serial:'PHOC2140009X118B',bus:'NVMe PCIe Gen3 x4',media:'ssd',size:118410207232,lbs:512,pbs:512,table:'gpt',tier:'fast',parts:[
        {id:'nvme2n1p1',num:1,start:MiB,size:32*GiB,fs:'zfs_member',label:'tank-slog',member:'tank',role:'log'}]},
      ...exos,
      {dev:'sdg',model:'WDC WD80EFZZ (Red Plus 8TB)',serial:'VK1A2B3C',bus:'SATA 6Gb/s',media:'hdd',size:8001563222016,lbs:512,pbs:4096,table:'gpt',tier:'mass',parts:[{id:'sdg1',num:1,start:MiB,size:'rest',fs:'linux_raid_member',label:'cold-a',member:'md0'}]},
      {dev:'sdh',model:'WDC WD80EFZZ (Red Plus 8TB)',serial:'VK1A9Q7D',bus:'SATA 6Gb/s',media:'hdd',size:8001563222016,lbs:512,pbs:4096,table:'gpt',tier:'mass',parts:[{id:'sdh1',num:1,start:MiB,size:'rest',fs:'linux_raid_member',label:'cold-b',member:'md0'}]},
      {dev:'sdi',model:'ST3000DM008 (Barracuda 3TB)',serial:'Z5059XYZ',bus:'SATA 6Gb/s',media:'hdd',size:3000592982016,lbs:512,pbs:4096,table:'mbr',tier:'mass',parts:[
        {id:'sdi1',num:1,start:63*512,size:2*TiB-63*512,fs:'ext4',label:'legacy',mount:'/mnt/legacy',opts:['defaults','discard']}]},
      {dev:'sdj',model:'LIO-ORG vmstore (iSCSI LUN 0)',serial:'iqn.2024-03.lan.nas02:vmstore',bus:'iSCSI LUN · 10GbE',media:'net',size:2*TiB,lbs:512,pbs:4096,table:'gpt',tier:'remote',parts:[
        {id:'sdj1',num:1,start:MiB,size:'rest',fs:'xfs',label:'vmstore',mount:'/mnt/iscsi_vm',opts:['_netdev','nofail','noatime']}]}
    ],
    pools:[
      {name:'tank',type:'zfs',level:'raidz2',ashift:12,tier:'mass',encryption:'aes-256-gcm',mount:'/mnt/storage_array',datasets:[
        {name:'media',mount:'/mnt/storage_array/media',recordsize:'1M',compression:'zstd',sync:'standard'},
        {name:'photos',mount:'/mnt/storage_array/photos',recordsize:'1M',compression:'zstd',sync:'standard'},
        {name:'vm',mount:'/mnt/storage_array/vm',recordsize:'64K',compression:'lz4',sync:'always'},
        {name:'backups',mount:'/mnt/storage_array/backups',recordsize:'1M',compression:'zstd',sync:'standard'}]},
      {name:'md0',type:'mdadm',level:'raid1',tier:'mass',fs:'ext4',label:'cold',mount:'/mnt/cold',opts:['noatime','nofail']}
    ],
    remotes:[
      {id:'nas02',name:'nas-02 archive',proto:'NFSv4.2',endpoint:'nas-02.tail4c2e.ts.net:/export/archive',via:'Tailscale',mount:'/mnt/remote_nfs',status:'connected',capacity:48e12,opts:['_netdev','x-systemd.automount','noatime','vers=4.2']},
      {id:'b2',name:'Backblaze B2 offsite',proto:'S3 (rclone)',endpoint:'b2:atlas-offsite',via:'Internet · TLS',mount:'/mnt/remote_s3',status:'connected',capacity:null,opts:['_netdev','x-systemd.automount','vfs_cache_mode=writes','config=/etc/rclone/rclone.conf','allow_other']},
      {id:'office',name:'office-nas archive',proto:'SMB3',endpoint:'//office-nas.nb.internal/archive',via:'NetBird',mount:'/mnt/archive',status:'disconnected',capacity:16e12,opts:['_netdev','x-systemd.automount','credentials=/etc/samba/office.cred','uid=1000','vers=3.1.1']}
    ],
    links:[
      {id:'L1',kind:'symlink',path:'/var/media',target:'/mnt/storage_array/media'},
      {id:'L2',kind:'bind',path:'/var/lib/docker',target:'/mnt/fast_scratch/docker'},
      {id:'L3',kind:'bind',path:'/var/lib/containerd',target:'/mnt/fast_scratch/containerd'},
      {id:'L4',kind:'symlink',path:'/home/ops/Pictures/RAW',target:'/mnt/storage_array/photos/raw'},
      {id:'L5',kind:'symlink',path:'/home/ops/Archive',target:'/mnt/archive/2019'},
      {id:'L6',kind:'symlink',path:'/opt/app/current',target:'/opt/app/releases/live'},
      {id:'L7',kind:'symlink',path:'/opt/app/releases/live',target:'/opt/app/current'},
      {id:'L8',kind:'hardlink',path:'/mnt/storage_array/media/movies/Arrival (2016).mkv',target:'/mnt/storage_array/media/downloads/Arrival (2016).mkv'},
      {id:'L9',kind:'symlink',path:'/srv/vm-images',target:'/mnt/iscsi_vm/images'}
    ],
    exports:[
      {id:'e1',proto:'NFSv4.2',name:'media',path:'/mnt/storage_array/media',clients:'100.64.0.0/10 (tailnet)',opts:'ro,no_subtree_check'},
      {id:'e2',proto:'SMB3',name:'photos',path:'/mnt/storage_array/photos',clients:'@lan-editors',opts:'vfs objects = shadow_copy2 zfsacl'},
      {id:'e3',proto:'S3',name:'restic (MinIO)',path:'/mnt/storage_array/backups',clients:'10.0.20.0/24',opts:'bucket=restic'},
      {id:'e4',proto:'SFTP',name:'drop (chroot)',path:'/mnt/cold/drop',clients:'sftp-users',opts:'ChrootDirectory %h'}
    ],
    existing:{'/var/lib/docker':'14.2 GiB of existing image layers'},
    known:['/opt/app/releases','/home/ops','/srv','/var/lib','/var/cache'],
    protection:[
      {node:'sv:nvme0n1p2/@',name:'@ (root)',sync:{state:'None'},snap:{on:true,tool:'snapper',policy:'hourly 24 · daily 7 · pre/post pacman',count:61,overhead:18.4*GiB},backup:{target:'restic → B2',enc:'restic AES-256',ratio:1.9,last:'2026-10-24',offsite:true}},
      {node:'sv:nvme0n1p2/@home',name:'@home',sync:{state:'Rsync Scheduled',target:'nas-02 nightly 02:30',offsite:true},snap:{on:true,tool:'snapper',policy:'hourly 12 · daily 14',count:26,overhead:9.1*GiB},backup:{target:'restic → B2',enc:'restic AES-256',ratio:1.4,last:'2026-10-24',offsite:true}},
      {node:'ds:tank/media',name:'tank/media',sync:{state:'Active Sync',target:'syncoid → nas-02/media',lag:'12 min',offsite:true},snap:{on:true,tool:'sanoid',policy:'daily 30 · monthly 6',count:36,overhead:212*GiB},backup:{target:null,enc:'ZFS native aes-256-gcm',ratio:1.01,last:null,offsite:false}},
      {node:'ds:tank/photos',name:'tank/photos',sync:{state:'Active Sync',target:'syncoid → nas-02/photos',lag:'9 min',offsite:true},snap:{on:true,tool:'sanoid',policy:'hourly 24 · daily 30 · monthly 12',count:66,overhead:41*GiB},backup:{target:'restic → B2',enc:'ZFS native + restic',ratio:1.03,last:'2026-10-19',offsite:true}},
      {node:'ds:tank/vm',name:'tank/vm',sync:{state:'Lagging',target:'syncoid → nas-02/vm',lag:'6 h 40 min',offsite:true},snap:{on:true,tool:'sanoid',policy:'frequent 4 · hourly 48',count:52,overhead:380*GiB},backup:{target:'PBS → pbs-02',enc:'PBS AES-256-GCM',ratio:2.3,last:'2026-07-02',offsite:true}},
      {node:'ds:tank/backups',name:'tank/backups',sync:{state:'Active Sync',target:'zfs send → nas-02',lag:'31 min',offsite:true},snap:{on:true,tool:'sanoid',policy:'daily 14 · weekly 8',count:22,overhead:66*GiB},backup:{target:'age → S3 Glacier IR',enc:'age X25519',ratio:1.0,last:'2026-10-01',offsite:true}},
      {node:'pool:md0',name:'md0 (cold)',sync:{state:'Disconnected',target:'rsync → office-nas',offsite:true},snap:{on:false,tool:'none (ext4)',policy:'',count:0,overhead:0},backup:{target:null,enc:'LUKS2 (aes-xts-plain64)',ratio:1,last:null,offsite:false}},
      {node:'part:nvme1n1p1',name:'fast_scratch',ephemeral:true,sync:{state:'None'},snap:{on:false,tool:'none',policy:'',count:0,overhead:0},backup:{target:null,enc:'none',ratio:1,last:null,offsite:false}},
      {node:'part:sdi1',name:'legacy',sync:{state:'None'},snap:{on:false,tool:'none',policy:'',count:0,overhead:0},backup:{target:null,enc:'none',ratio:1,last:null,offsite:false}},
      {node:'part:sdj1',name:'iscsi_vm',sync:{state:'None'},snap:{on:true,tool:'zvol snapshots on nas-02',policy:'daily 7',count:7,overhead:22*GiB},backup:{target:'PBS → pbs-02',enc:'PBS AES-256-GCM',ratio:2.1,last:'2026-10-20',offsite:false}}
    ]
  };
  normalize(s); return s;
}
function normalize(s){
  s.disks.forEach(d=>d.parts.forEach(p=>{ if(p.size==='rest') p.size=Math.floor((d.size-p.start-(d.table==='gpt'?MiB:0))/MiB)*MiB; }));
}
/* ───────────── documents: the example, or a host's design from the server ───────────── */
// DOC.host is '' for the built-in example. Every edit is kept as a per-host draft in this browser until saved.
const DOC={host:'',source:'example',dirty:false,savedAt:null,scanned:false,hosts:[],signedIn:false,example:true,activity:null};
sfUnsaved({ id: 'planner', label: 'the planner edits', kept: true, dirty: () => DOC.dirty });      // save() keeps a draft per host in this browser
// the example stays when there is nothing else to show, even after it is removed
const exampleShown=()=>DOC.example||!DOC.hosts.length;
const draftKey=h=>'storageforge.v1'+(h?':'+h:'');
function load(h){ try{ const t=localStorage.getItem(draftKey(h||'')); return t?tidy(scrub(JSON.parse(t))):null }catch(e){ return null } }
function save(){ try{ localStorage.setItem(draftKey(DOC.host),JSON.stringify(S)) }catch(e){} if(DOC.host){DOC.dirty=true;docState()} }
function dropDraft(h){ try{ localStorage.removeItem(draftKey(h)) }catch(e){} }
let S=load('')||sample();

const UI={view:'overview',sel:null,mountSel:'/',mountTab:'fstab',exportTab:'changes',diff:null,calc:null,hover:null};
const VIEWS=[
  ['overview','Overview','Capacity, protection, every guardrail, and what is staged or deployed on the host.'],
  ['devices','Devices','Block devices, partition tables and filesystems. Select a partition, pool or remote to edit it.'],
  ['mounts','Mounts','Mount hierarchy, conflict checks, and the generated /etc/fstab and systemd units.'],
  ['links','Links','Symlinks, bind mounts and hard links, with health checks and boot ordering.'],
  ['topology','Topology','Drives → pools → datasets → mount points → links and exports. Hover a node to trace it.'],
  ['raid','RAID calculator','Usable space, parity, padding, rebuild exposure and write amplification.'],
  ['protection','Protection','3-2-1 matrix: sync, snapshots and offsite backups per dataset.'],
  ['export','Export','The change plan that brings the host to this design, plus fstab, units and blueprints.']
];

/* ───────────── model helpers ───────────── */
const MOUNTABLE=['vfat','ext4','xfs','btrfs','f2fs'];
const FS_LIST=['vfat','ext4','xfs','btrfs','f2fs','swap','none'];
const OPTS={
  ext4:['defaults','noatime','nofail','discard','errors=remount-ro','commit=60','data=writeback'],
  xfs:['noatime','nofail','discard','inode64','logbsize=256k','largeio'],
  btrfs:['noatime','compress=zstd:3','discard=async','ssd','space_cache=v2','autodefrag','nofail'],
  f2fs:['noatime','lazytime','compress_algorithm=zstd','compress_chksum','atgc','gc_merge','discard','nofail'],
  vfat:['umask=0077','noatime','nofail'],
  swap:['sw','discard','pri=10'],
  net:['_netdev','x-systemd.automount','nofail','noatime']
};
const DANGER_OPTS=['data=writeback','discard','nobarrier'];
const allParts=()=>S.disks.flatMap(d=>d.parts.map(p=>({p,d})));
const findPart=id=>allParts().find(x=>x.p.id===id);
const poolBy=n=>S.pools.find(p=>p.name===n);
const diskBy=n=>S.disks.find(d=>d.dev===n);
const remoteBy=id=>S.remotes.find(r=>r.id===id);
const isUnder=(p,root)=>root==='/'?p.startsWith('/'):(p===root||p.startsWith(root+'/'));
function specFor(p){ if(S.idMode==='LABEL'&&p.label) return 'LABEL='+p.label; if(p.uuid) return 'UUID='+p.uuid; return 'UUID='+(p.fs==='vfat'?shortUUID(p.id):fakeUUID(p.id)); }
const remoteFs=r=>r.proto.startsWith('NFS')?'nfs4':r.proto.startsWith('SMB')?'cifs':'rclone';

const POOL_KIND={zfs:'OpenZFS',btrfs:'Btrfs',lvm:'LVM RAID',mdadm:'mdadm'};
const lvPath=p=>p.vg&&p.lv?`/dev/${p.vg}/${p.lv}`:'/dev/'+p.name;
function poolMembers(pool){
  const whole=S.disks.filter(d=>d.member===pool.name).map(d=>({id:d.dev,size:d.size,disk:d,whole:true}));
  const parts=allParts().filter(x=>x.p.member===pool.name).map(x=>({id:x.p.id,size:x.p.size,disk:x.d,role:x.p.role||'data',part:x.p}));
  return {data:[...whole,...parts.filter(x=>x.role==='data')],log:parts.filter(x=>x.role==='log'),cache:parts.filter(x=>x.role==='cache')};
}
function poolCalc(pool){
  const m=poolMembers(pool);
  const width=pool.level==='mirror'?2:m.data.length;
  const layout=pool.type==='zfs'?'zfs-'+pool.level:pool.type==='btrfs'?'btrfs-'+(['single','raid1','raid1c3','raid10'].includes(pool.level)?pool.level:'single'):'md-'+(['raid0','raid1','raid5','raid6','raid10'].includes(pool.level)?pool.level:'raid0');
  return {layout,sizes:m.data.map(x=>x.size),width,recordsize:128*1024,ashift:pool.ashift||12,fill:0.7,speed:180,ure:1e-15,fs:pool.fs||'ext4',reserve:true,virt:0};
}
function isRedundantPool(pool){ return pool && !['stripe','raid0','linear'].includes(pool.level) }

function collectMounts(){
  const M=[];
  S.disks.forEach(d=>d.parts.forEach(p=>{
    if(p.fs==='btrfs'&&p.subvols&&p.subvols.length){
      p.subvols.forEach(sv=>{ if(sv.mount) M.push({target:sv.mount,node:`sv:${p.id}/${sv.name}`,kind:'subvol',fs:'btrfs',opts:['subvol='+sv.name,...(p.opts||[])],spec:specFor(p),dev:'/dev/'+p.id,part:p,disk:d,tier:d.tier,desc:`btrfs subvolume ${sv.name} on ${p.label}`}) });
    } else if(p.fs==='swap'){
      M.push({target:'none',node:'part:'+p.id,kind:'swap',fs:'swap',opts:p.opts&&p.opts.length?p.opts:['sw'],spec:specFor(p),dev:'/dev/'+p.id,part:p,disk:d,tier:d.tier,desc:'swap'});
    } else if(p.mount&&MOUNTABLE.includes(p.fs)){
      M.push({target:p.mount,node:'part:'+p.id,kind:'block',fs:p.fs,opts:p.opts||[],spec:specFor(p),dev:'/dev/'+p.id,part:p,disk:d,tier:d.tier,desc:`${p.fs} ${p.label||p.id}`});
    }
  }));
  S.pools.forEach(pool=>{
    if(pool.type==='zfs'){
      if(pool.mount) M.push({target:pool.mount,node:'pool:'+pool.name,kind:'zfs',fs:'zfs',opts:[],spec:pool.name,dev:pool.name,pool,tier:pool.tier,desc:`ZFS pool root ${pool.name}`});
      (pool.datasets||[]).forEach(ds=>{ if(ds.mount) M.push({target:ds.mount,node:`ds:${pool.name}/${ds.name}`,kind:'zfs',fs:'zfs',opts:[],spec:`${pool.name}/${ds.name}`,dev:`${pool.name}/${ds.name}`,pool,ds,tier:pool.tier,desc:`ZFS dataset ${pool.name}/${ds.name}`}) });
    } else if(pool.type==='lvm'&&!pool.lv){
      (pool.datasets||[]).forEach(ds=>{const dev=`/dev/${pool.vg}/${ds.name}`;
        if(ds.fs==='swap') M.push({target:'none',node:`ds:${pool.name}/${ds.name}`,kind:'swap',fs:'swap',opts:['sw'],spec:dev,dev,pool,ds,tier:pool.tier,desc:`swap on LVM ${pool.vg}/${ds.name}`});
        else if(ds.mount) M.push({target:ds.mount,node:`ds:${pool.name}/${ds.name}`,kind:'block',fs:ds.fs,opts:ds.opts||[],spec:dev,dev,pool,ds,tier:pool.tier,desc:`${ds.fs} on LVM ${pool.vg}/${ds.name}`})});
    } else if(pool.mount){
      M.push({target:pool.mount,node:'pool:'+pool.name,kind:'md',fs:pool.fs,opts:pool.opts||[],spec:S.idMode==='LABEL'&&pool.label?'LABEL='+pool.label:'UUID='+fakeUUID(pool.name+'-fs'),dev:lvPath(pool),pool,tier:pool.tier,desc:`${pool.fs} on ${POOL_KIND[pool.type]||'mdadm'} ${pool.level} ${pool.vg?pool.vg+'/'+pool.lv:pool.name}`});
    }
  });
  S.remotes.forEach(r=>{ if(r.mount) M.push({target:r.mount,node:'rem:'+r.id,kind:'remote',fs:remoteFs(r),opts:r.opts||[],spec:r.endpoint,dev:r.endpoint,remote:r,tier:'remote',desc:`${r.proto} via ${r.via}`}) });
  S.links.filter(l=>l.kind==='bind').forEach(l=>{
    const src=containingMount(l.target,M);
    M.push({target:l.path,node:'link:'+l.id,kind:'bind',fs:'none',opts:['bind',...(src&&src.target!=='/'?['x-systemd.requires-mounts-for='+src.target]:[])],spec:l.target,dev:l.target,link:l,tier:src?src.tier:'fast',desc:'bind mount of '+l.target});
  });
  return M;
}
function containingMount(path,M){
  M=M||collectMounts();
  let best=null;
  M.forEach(m=>{ if(m.kind==='bind'||m.kind==='swap') return; if(isUnder(path,m.target)&&(!best||m.target.length>best.target.length)) best=m; });
  return best;
}

/* graph of everything: disk → part → pool/subvol → dataset → mount → link/export */
function buildGraph(){
  const E=[];const add=(a,b,k)=>E.push([a,b,k||'']);
  const M=collectMounts();
  S.disks.forEach(d=>{
    if(d.member) add('disk:'+d.dev,'pool:'+d.member);
    d.parts.forEach(p=>{
      add('disk:'+d.dev,'part:'+p.id);
      if(p.member) add('part:'+p.id,'pool:'+p.member,p.role==='cache'||p.role==='log'?'cache':'');
      if(p.fs==='btrfs'&&p.subvols&&p.subvols.length) p.subvols.forEach(sv=>{ add('part:'+p.id,`sv:${p.id}/${sv.name}`); if(sv.mount) add(`sv:${p.id}/${sv.name}`,'mnt:'+sv.mount) });
      else if(p.mount&&MOUNTABLE.includes(p.fs)) add('part:'+p.id,'mnt:'+p.mount);
    });
  });
  S.pools.forEach(pool=>{
    if(pool.mount) add('pool:'+pool.name,'mnt:'+pool.mount);
    (pool.datasets||[]).forEach(ds=>{ add('pool:'+pool.name,`ds:${pool.name}/${ds.name}`); if(ds.mount) add(`ds:${pool.name}/${ds.name}`,'mnt:'+ds.mount) });
  });
  S.remotes.forEach(r=>{ if(r.mount) add('rem:'+r.id,'mnt:'+r.mount) });
  S.links.forEach(l=>{ const m=containingMount(l.target,M); if(m) add('mnt:'+m.target,'link:'+l.id) });
  S.exports.forEach(e=>{ const m=containingMount(e.path,M); if(m) add('mnt:'+m.target,'exp:'+e.id) });
  return E;
}
function chainOf(id){
  const E=buildGraph();const set=new Set([id]);
  // mount rows carry the source node (sv:/part:/ds:); treat the mount node as part of the same chain
  let q=[id];while(q.length){const n=q.pop();E.forEach(([a,b])=>{if(b===n&&!set.has(a)){set.add(a);q.push(a)}})}
  q=[id];const down=new Set([id]);while(q.length){const n=q.pop();E.forEach(([a,b])=>{if(a===n&&!down.has(b)){down.add(b);set.add(b);q.push(b)}})}
  return set;
}
function nodeLabel(id){
  const [t,...r]=id.split(':');const v=r.join(':');
  if(t==='disk'||t==='part') return '/dev/'+v;
  if(t==='sv') return 'subvol '+v.split('/').slice(1).join('/');
  if(t==='pool'){const p=poolBy(v);return p?`${v} (${p.type} ${p.level})`:v}
  if(t==='ds') return v;
  if(t==='mnt') return v;
  if(t==='link'){const l=S.links.find(x=>x.id===v);return l?`${l.kind} ${l.path}`:v}
  if(t==='rem'){const x=remoteBy(v);return x?x.endpoint:v}
  if(t==='exp'){const e=S.exports.find(x=>x.id===v);return e?`${e.proto} ${e.name}`:v}
  return id;
}
const TORDER=['disk','rem','part','pool','sv','ds','mnt','link','exp'];

/* ───────────── RAID / pool engine ───────────── */
function raidzEff(w,P,rs,ashift){const S_=2**ashift;const d=Math.ceil(rs/S_);const p=P*Math.ceil(d/(w-P));const tot=Math.ceil((d+p)/(P+1))*(P+1);return {eff:d/tot,d,tot}}
function btrfsAlloc(sizes,copies,raid10){
  const free=sizes.slice();const chunk=Math.max(...sizes)/1500;let cap=0;
  for(let it=0;it<200000;it++){
    const idx=free.map((f,i)=>i).filter(i=>free[i]>=chunk).sort((a,b)=>free[b]-free[a]);
    if(raid10){let k=idx.length-idx.length%2;if(k<4)break;idx.slice(0,k).forEach(i=>free[i]-=chunk);cap+=chunk*k/2}
    else{if(idx.length<copies)break;idx.slice(0,copies).forEach(i=>free[i]-=chunk);cap+=chunk}
  }
  return cap;
}
const FS_OVH={ext4:r=>(r?0.05:0)+0.0156,xfs:()=>0.008,btrfs:()=>0.01};
function calcEngine(c){
  const sizes=c.sizes.filter(x=>x>0);const n=sizes.length;const raw=sum(sizes);
  const r={raw,usable:0,data:0,parity:0,overhead:0,waste:0,unused:0,tol:0,tolNote:'',rebuildH:0,ureP:0,ureLevel:'',waSeq:1,waSmall:1,waNote:'',notes:[],padPct:0};
  const [fam,lvl]=c.layout.split('-');
  if(!n){r.notes.push(['crit','Add at least one drive.']);return r}
  const mn=a=>Math.min(...a);
  const maxD=Math.max(...sizes);
  let readers=0,fill=1;
  if(fam==='zfs'){
    const P={stripe:0,mirror:0,raidz1:1,raidz2:2,raidz3:3}[lvl];
    let w=lvl==='stripe'?1:lvl==='mirror'?Math.max(2,Math.min(c.width||2,n)):Math.max(P+1,Math.min(c.width||n,n));
    const minW={stripe:1,mirror:2,raidz1:3,raidz2:4,raidz3:5}[lvl];
    if(n<minW){r.notes.push(['crit',`${lvl} needs at least ${minW} drives; you have ${n}.`]);return r}
    if(w<minW) w=minW;
    const g=Math.floor(n/w);let pad=0;
    for(let i=0;i<g;i++){
      const v=sizes.slice(i*w,i*w+w);const m=mn(v);r.waste+=sum(v)-m*w;
      if(lvl==='mirror'){r.data+=m;r.parity+=m*(w-1)}
      else if(lvl==='stripe'){r.data+=m}
      else{const {eff}=raidzEff(w,P,c.recordsize,c.ashift);const nominal=(w-P)*m;const actual=m*w*eff;r.data+=actual;r.parity+=m*P;pad+=nominal-actual}
    }
    r.unused=sum(sizes.slice(g*w));
    r.overhead+=pad;r.padPct=pad/raw*100;
    const slop=Math.min(r.data/32,128*GiB);r.data-=slop;r.overhead+=slop;
    r.tol=lvl==='mirror'?w-1:P;
    r.tolNote=lvl==='stripe'?'Any drive loss destroys the pool':g>1?`${r.tol} per vdev · up to ${r.tol*g} if failures land in different vdevs`:`${r.tol} drive${r.tol===1?'':'s'} in the vdev`;
    fill=c.fill;readers=w-1;
    if(lvl==='mirror'){r.waSeq=w;r.waSmall=w;r.waNote=`each write lands on all ${w} mirrors`}
    else if(lvl==='stripe'){r.waSeq=1;r.waSmall=1;r.waNote='no redundancy writes'}
    else{const {d,tot}=raidzEff(w,P,c.recordsize,c.ashift);r.waSeq=tot/d;r.waSmall=1+P;r.waNote=`record ${fmtBin(c.recordsize,0)} → ${d} data + ${tot-d} parity/pad sectors; a 4K write costs ${1+P} sectors`}
    if(c.ashift<12) r.notes.push(['warn','ashift=9 on 4K-sector drives forces read-modify-write inside the drive. Use ashift=12 (or 13 for some SSDs). It cannot be changed after vdev creation.']);
    if(lvl==='raidz1'&&maxD>=8e12) r.notes.push(['warn',`RAIDZ1 with ${fmtDec(maxD,0)} drives leaves no parity during a ${Math.round(maxD*c.fill/(c.speed*1e6)/3600)} h resilver. RAIDZ2 is the usual floor at this size.`]);
    if(r.padPct>4) r.notes.push(['info',`RAIDZ padding costs ${r.padPct.toFixed(1)}% of raw at recordsize ${fmtBin(c.recordsize,0)}. Larger records or a different width reduce it.`]);
    if(g*w<n) r.notes.push(['info',`${n-g*w} drive(s) do not fill a ${w}-wide vdev and stay unused (use as hot spares).`]);
  } else if(fam==='md'){
    const m=mn(sizes);r.waste=raw-m*n;
    const need={raid0:2,raid1:2,raid5:3,raid6:4,raid10:4}[lvl];
    if(n<need){r.notes.push(['crit',`mdadm ${lvl} needs at least ${need} drives.`]);return r}
    if(lvl==='raid0'){r.data=n*m;r.tol=0;readers=0;r.waSeq=1;r.waSmall=1;r.waNote='striped, no redundancy'}
    if(lvl==='raid1'){r.data=m;r.parity=(n-1)*m;r.tol=n-1;readers=1;r.waSeq=n;r.waSmall=n;r.waNote=`every write goes to ${n} drives`}
    if(lvl==='raid5'){r.data=(n-1)*m;r.parity=m;r.tol=1;readers=n-1;r.waSeq=n/(n-1);r.waSmall=4;r.waNote='partial-stripe write: 2 reads + 2 writes (RMW)'}
    if(lvl==='raid6'){r.data=(n-2)*m;r.parity=2*m;r.tol=2;readers=n-1;r.waSeq=n/(n-2);r.waSmall=6;r.waNote='partial-stripe write: 3 reads + 3 writes (RMW)'}
    if(lvl==='raid10'){r.data=n*m/2;r.parity=n*m/2;r.tol=1;readers=1;r.waSeq=2;r.waSmall=2;r.waNote='near-2 layout, each block written twice'}
    r.tolNote=lvl==='raid10'?`1 guaranteed · up to ${Math.floor(n/2)} if in different mirror pairs`:lvl==='raid0'?'Any drive loss destroys the array':`${r.tol} drive${r.tol===1?'':'s'}`;
    const o=r.data*(FS_OVH[c.fs]||FS_OVH.ext4)(c.reserve);r.overhead+=o;r.data-=o;
    if(lvl==='raid5') r.notes.push(['warn','mdadm RAID5 has a write hole on power loss unless a journal device or PPL is configured (--consistency-policy=ppl).']);
    if(c.fs==='ext4'&&c.reserve) r.notes.push(['info','ext4 reserves 5% for root by default. On a data-only array, mkfs.ext4 -m 0 or -m 1 recovers most of it.']);
  } else if(fam==='btrfs'){
    const copies={single:1,raid1:2,raid1c3:3,raid10:2}[lvl];const need={single:1,raid1:2,raid1c3:3,raid10:4}[lvl];
    if(n<need){r.notes.push(['crit',`btrfs ${lvl} needs at least ${need} devices.`]);return r}
    r.data=lvl==='single'?raw:btrfsAlloc(sizes,copies,lvl==='raid10');
    r.parity=r.data*(copies-1);r.waste=Math.max(0,raw-r.data*copies);
    r.tol=copies-1;r.tolNote=r.tol?`${r.tol} device${r.tol>1?'s':''} (chunk-level copies)`:'Any device loss loses data';
    const o=r.data*0.01+512*MiB;r.overhead+=o;r.data-=o;
    fill=c.fill;readers=1;r.waSeq=copies;r.waSmall=copies;r.waNote=`${copies} copies per chunk, plus CoW metadata updates`;
    if(r.waste>0.01*raw) r.notes.push(['info',`Mixed sizes: ${fmtDec(r.waste)} cannot be paired with another device and stays unallocatable.`]);
  } else if(fam==='lvm'){
    r.data=raw;r.tol=0;r.tolNote='Linear concatenation, any PV loss damages the LV';r.waSeq=1;r.waSmall=1;r.waNote='no redundancy writes';
    if(lvl==='thin'){const md=Math.min(raw*0.001,16*GiB);r.overhead+=md;r.data-=md;
      const ratio=c.virt?c.virt/r.data:0;
      if(ratio>1) r.notes.push([ratio>1.5?'warn':'info',`Thin pool is overcommitted ${ratio.toFixed(2)}× (${fmtDec(c.virt)} virtual on ${fmtDec(r.data)}). Set thin_pool_autoextend_threshold and monitor data_percent.`]);
    }
    const o=r.data*(FS_OVH[c.fs]||FS_OVH.ext4)(c.reserve);r.overhead+=o;r.data-=o;
    r.notes.push(['warn','LVM linear and thin pools have no redundancy of their own. Put them on top of mdadm or hardware RAID.']);
  }
  r.usable=Math.max(0,r.data);
  if(r.waste>0&&fam!=='btrfs') r.notes.push(['info',`Mixed drive sizes waste ${fmtDec(r.waste)}: each vdev/array is limited by its smallest member.`]);
  if(r.tol===0) r.notes.unshift(['crit','No fault tolerance. One failed drive loses data on this layout.']);
  r.rebuildH=r.tol?maxD*fill/(c.speed*1e6)/3600:0;
  const bits=readers*maxD*fill*8;r.ureP=r.tol?1-Math.exp(-bits*c.ure):0;
  r.ureLevel=!r.tol?'n/a':r.tol>=2?'Low':r.ureP<0.01?'Low':r.ureP<0.1?'Moderate':'High';
  if(r.tol===1&&r.ureP>0.1) r.notes.push(['warn',`During a rebuild ${readers} drive(s) are read end to end. At URE 1 in ${(1/c.ure).toExponential(0)} bits that is a ${(r.ureP*100).toFixed(0)}% chance of an unrecoverable sector with no parity left.`]);
  return r;
}

/* ───────────── protection ───────────── */
const SYNC_STATES=['Active Sync','Rsync Scheduled','Lagging','Disconnected','None'];
function protStatus(row){
  if(row.ephemeral) return {k:'muted',t:'Excluded',why:['Marked ephemeral scratch space']};
  const why=[];const age=row.backup.target?daysSince(row.backup.last):Infinity;
  const badSync=['Lagging','Disconnected'].includes(row.sync.state);
  const replica=['Active Sync','Rsync Scheduled'].includes(row.sync.state)&&row.sync.offsite===true;
  if(row.sync.state==='Lagging') why.push(`Replication lagging ${row.sync.lag||''}`.trim());
  if(row.sync.state==='Disconnected') why.push('Replication target unreachable');
  if(row.backup.target&&age>90) why.push(`Backup not validated for ${age} days`);
  const nothing=!row.snap.on&&!row.backup.target&&row.sync.state==='None';
  if(nothing) why.push('Single copy: no snapshots, sync or backup');
  if(badSync||(row.backup.target&&age>90)||nothing||(!row.snap.on&&!row.backup.target)) { if(!why.length) why.push('No snapshots and no backup'); return {k:'crit',t:'Critical',why} }
  if(row.snap.on&&row.backup.target&&row.backup.offsite&&age<=30) return {k:'ok',t:'Protected',why:['Snapshots, offsite backup validated '+(age===0?'today':age+' d ago')]};
  if(!row.backup.target) why.push(replica?'No backup target: the replica is a copy, not a backup':'No backup target'); else if(!row.backup.offsite) why.push('Backup is not offsite'); else if(age>30) why.push(`Validation ${age} d old`);
  if(!row.snap.on) why.push('No snapshots');
  return {k:'warn',t:'Local only',why};
}
function copies321(row){
  const syncOk=['Active Sync','Rsync Scheduled'].includes(row.sync.state);
  const c=1+(syncOk?1:0)+(row.backup.target?1:0);
  // offsite is what the design or the deploy says: a backup's flag (the host it runs on is marked offsite), or a sync's own flag. A name proves nothing (UX-32).
  const off=!!row.backup.offsite||(syncOk&&row.sync.offsite===true);
  const unstated=!off&&syncOk&&row.sync.offsite===undefined;      // a replica nobody said anything about: not offsite, and not known to be local either
  return {c,off,unstated};
}

/* ───────────── link health & guardrails ───────────── */
function pathStatus(p,M){
  const m=containingMount(p,M);
  if(!m) return {state:'crit',msg:'No filesystem contains this path'};
  if(m.kind==='remote'&&m.remote.status!=='connected') return {state:'crit',msg:`Target sits on ${m.target}, which is disconnected (${m.remote.via})`,m};
  if(m.target==='/'&&!S.known.some(k=>isUnder(p,k))&&!S.links.some(l=>l.path===p)) return {state:'crit',msg:'Target path does not exist on the root filesystem',m};
  return {state:'ok',msg:`Resolves on ${m.target}`,m};
}
function linkHealth(l,M){
  M=M||collectMounts();
  if(l.kind==='symlink'){
    const seen=[l.path];let t=l.target;
    for(let i=0;i<40;i++){const nx=S.links.find(x=>x.kind==='symlink'&&x.path===t);if(!nx)break;if(seen.includes(nx.path)) return {state:'crit',msg:'Circular symlink: '+[...seen,nx.path].join(' → ')+' (ELOOP)'};seen.push(nx.path);t=nx.target}
    return pathStatus(t,M);
  }
  if(l.kind==='bind'){
    if(isUnder(l.path,l.target)) return {state:'crit',msg:'Bind target is inside its own source, which makes a recursive mount'};
    const st=pathStatus(l.target,M);if(st.state!=='ok') return st;
    if(S.existing[l.path]) return {state:'warn',msg:`Mounting over ${l.path} hides ${S.existing[l.path]}. Migrate it first.`,m:st.m};
    return st;
  }
  const a=containingMount(l.path,M),b=containingMount(l.target,M);
  if(!a||!b||a.target!==b.target) return {state:'crit',msg:`Hard link crosses filesystems (${a?a.target:'?'} vs ${b?b.target:'?'}), which fails with EXDEV`};
  return {state:'ok',msg:`Same filesystem (${a.target})`,m:a};
}
function analyze(){
  const A=[];const push=(sev,title,detail,node,view)=>A.push({sev,title,detail,node,view});
  const M=collectMounts();const MM=M.filter(m=>m.kind!=='swap');
  const byT={};MM.forEach(m=>(byT[m.target]=byT[m.target]||[]).push(m));
  Object.entries(byT).forEach(([t,ms])=>{ if(ms.length>1) push('crit',`Duplicate mount point ${t}`,`${ms.map(m=>m.desc).join(' and ')} both mount at ${t}. The later one shadows the earlier one at boot.`,ms[0].node,'mounts') });
  MM.forEach(m=>{ if(!m.target.startsWith('/')) push('crit',`Mount target "${m.target}" is not an absolute path`,'fstab and systemd require absolute mount points.',m.node,'mounts') });
  // root
  const root=MM.find(m=>m.target==='/');
  if(!root) push('crit','No root filesystem','Nothing in the blueprint mounts at /.',null,'mounts');
  else{
    const red=root.pool?isRedundantPool(root.pool):false;
    const prow=S.protection.find(r=>r.node===root.node);const snap=prow&&prow.snap.on;
    if(!red&&!snap) push('crit','Root on non-redundant media without snapshots',`/ lives on ${root.dev} (${root.disk?root.disk.model:'single device'}) with no snapshots. A bad upgrade or drive failure means a full reinstall.`,root.node,'protection');
    else if(!red) push('warn','Root is on a single device',`/ is snapshotted (${prow.snap.tool}) but ${root.disk?'/dev/'+root.disk.dev:'its device'} has no mirror. Snapshots cover bad upgrades, not drive failure, so keep the offsite backup validated.`,root.node,'protection');
  }
  // disks & partitions
  S.disks.forEach(d=>{
    if(d.table==='mbr'&&d.size>2*TiB) push('warn',`/dev/${d.dev} uses MBR on a ${fmtDec(d.size,0)} disk`,`MBR addresses only 2 TiB with 512-byte sectors, so ${fmtBin(d.size-2*TiB)} is unreachable. Convert with sgdisk -g after a backup.`,'disk:'+d.dev,'devices');
    d.parts.forEach(p=>{
      if(p.start%MiB!==0){const bad4k=p.start%d.pbs!==0;push(bad4k?'crit':'warn',`/dev/${p.id} is misaligned (starts at sector ${p.start/512})`,bad4k?`Start is not a multiple of the ${d.pbs}-byte physical sector, so every 4K write becomes a read-modify-write inside the drive. Recreate at 1 MiB (sector 2048).`:'Start is not on a 1 MiB boundary. Recreate the partition at 2048s.',`part:${p.id}`,'devices');}
      if(d.media==='hdd'&&(p.opts||[]).some(o=>o.startsWith('discard'))) push('warn',`discard on spinning disk /dev/${p.id}`,`${d.model} is a hard drive. TRIM does nothing there, and some SATA bridges error on it. Remove the discard option.`,`part:${p.id}`,'devices');
      if((p.opts||[]).includes('data=writeback')) push('warn',`data=writeback on /dev/${p.id}`,'Metadata can commit before data, so a crash can leave stale blocks in recently written files.',`part:${p.id}`,'devices');
    });
    if(d.bus.startsWith('iSCSI')) d.parts.forEach(p=>{ if(p.mount&&!(p.opts||[]).includes('_netdev')) push('crit',`iSCSI volume ${p.mount} lacks _netdev`,'Without _netdev, systemd tries to mount it before the network and iscsid are up, which hangs boot for 90 s and then drops to emergency mode.',`part:${p.id}`,'devices') });
  });
  S.pools.forEach(pool=>{
    if(pool.type==='zfs'){
      const m=poolMembers(pool);const pbs=Math.max(...m.data.map(x=>x.disk.pbs));
      if(2**(pool.ashift||12)<pbs) push('crit',`Pool ${pool.name}: ashift=${pool.ashift} below ${pbs}-byte sectors`,'Every write becomes a sub-sector write. ashift is fixed at vdev creation; set 12 before zpool create.','pool:'+pool.name,'devices');
      (pool.datasets||[]).forEach(ds=>{ if(ds.sync==='disabled') push('warn',`${pool.name}/${ds.name} has sync=disabled`,'Applications that fsync (databases, VMs, NFS clients) lose up to 5 s of acknowledged writes on power loss.',`ds:${pool.name}/${ds.name}`,'devices') });
      if(!isRedundantPool(pool)) push('crit',`Pool ${pool.name} is a plain stripe`,'One drive failure destroys the whole pool.','pool:'+pool.name,'devices');
    }
  });
  MM.forEach(m=>{ if(m.kind!=='bind'&&S.existing[m.target]) push('warn',`${m.target} is not empty`,`Mounting ${m.desc} there hides ${S.existing[m.target]}.`,m.node,'mounts') });
  MM.forEach(m=>{ const parent=MM.filter(x=>x!==m&&x.target!==m.target&&isUnder(m.target,x.target)).sort((a,b)=>b.target.length-a.target.length)[0];
    if(parent&&parent.kind==='remote'&&m.kind!=='remote') push('warn',`${m.target} is nested under network mount ${parent.target}`,'A local mount below an automounted network share forces the share to mount at boot and fails when the tunnel is down.',m.node,'mounts') });
  S.remotes.forEach(r=>{ if(r.status!=='connected') push('warn',`${r.name} is disconnected`,`${r.proto} ${r.endpoint} via ${r.via} is unreachable. Anything stored or linked under ${r.mount} is unavailable.`,'rem:'+r.id,'devices') });
  S.links.forEach(l=>{ const h=linkHealth(l,M); if(h.state!=='ok') push(h.state,`${l.kind} ${l.path}`,h.msg,'link:'+l.id,'links') });
  S.protection.forEach(r=>{ const st=protStatus(r); if(st.k==='crit') push('crit',`${r.name} protection is critical`,st.why.join('. ')+'.',r.node,'protection') });
  const ord={crit:0,warn:1,info:2};A.sort((a,b)=>ord[a.sev]-ord[b.sev]);
  return A;
}

/* boot ordering */
function stages(){
  const M=collectMounts().filter(m=>m.kind!=='swap');
  const deps=new Map();
  M.forEach(m=>{
    const d=[];
    const parent=M.filter(x=>x!==m&&x.target!==m.target&&isUnder(m.target,x.target)).sort((a,b)=>b.target.length-a.target.length)[0];
    if(parent) d.push(parent);
    if(m.kind==='bind'){const src=containingMount(m.spec,M);if(src&&src!==parent) d.push(src)}
    deps.set(m,d);
  });
  const lvl=new Map();const get=(m,stack=[])=>{ if(lvl.has(m)) return lvl.get(m); if(stack.includes(m)) return 0; const v=deps.get(m).length?1+Math.max(...deps.get(m).map(x=>get(x,[...stack,m]))):0; lvl.set(m,v); return v };
  M.forEach(m=>get(m));
  const out=[];M.forEach(m=>{const l=lvl.get(m);(out[l]=out[l]||[]).push({m,deps:deps.get(m)})});
  return out.map(a=>(a||[]).sort((x,y)=>x.m.target.localeCompare(y.m.target)));
}
const SERVICE_HINT={'/var/lib/docker':'docker.service','/var/lib/containerd':'containerd.service','/var/lib/postgresql':'postgresql.service','/var/lib/libvirt':'libvirtd.service','/var/log/app':'app.service','/var/cache/app':'app.service','/srv/vm-images':'libvirtd.service','/var/media':'jellyfin.service'};

/* ───────────── generators ───────────── */
function sdEscape(path){
  if(path==='/') return '-';
  return path.replace(/^\/+|\/+$/g,'').split('/').map(seg=>seg.replace(/[^A-Za-z0-9:_.]/g,c=>'\\x'+c.charCodeAt(0).toString(16).padStart(2,'0')).replace(/^\./,'\\x2e')).join('-');
}
const passFor=m=>['ext4','vfat'].includes(m.fs)?(m.target==='/'?1:2):0;
function genFstab(){
  const M=collectMounts();const L=[];
  L.push(`# /etc/fstab — generated by StorageForge for ${S.host} on ${today()}`);
  L.push(`# Identifiers: ${S.idMode}=  ·  ZFS datasets are mounted by zfs-mount.service and are listed as comments only.`);
  L.push('# <spec>  <mount point>  <type>  <options>  <dump>  <pass>');
  const groups=[['Fast tier',m=>m.tier==='fast'&&m.kind!=='bind'],['Mass tier',m=>m.tier==='mass'&&m.kind!=='bind'],['Remote / mesh',m=>m.tier==='remote'&&m.kind!=='bind'],['Bind mounts',m=>m.kind==='bind']];
  groups.forEach(([g,f])=>{
    const ms=M.filter(f);if(!ms.length) return;
    L.push('',`# ── ${g} ${'─'.repeat(Math.max(4,56-g.length))}`);
    ms.sort((a,b)=>a.target.split('/').length-b.target.split('/').length||a.target.localeCompare(b.target)).forEach(m=>{
      if(m.kind==='zfs'){L.push(`# zfs: ${m.spec.padEnd(22)} ${m.target}  (mountpoint property)`);return}
      if(m.disk) L.push(`# /dev/${m.part.id} · ${m.disk.model} · SN ${m.disk.serial}`);
      if(m.kind==='remote') L.push(`# ${m.remote.name} · ${m.remote.proto} via ${m.remote.via}`);
      const opts=(m.opts.length?m.opts:['defaults']).join(',');
      L.push([fstabEsc(m.spec),fstabEsc(m.target),fstabEsc(m.fs),fstabEsc(opts),0,passFor(m)].join('  '));
    });
  });
  return L.join('\n');
}
function unitFor(m){
  const name=sdEscape(m.target);const L=[];
  const what=m.kind==='remote'?m.spec:m.kind==='bind'?m.spec:m.spec.startsWith('UUID=')?'/dev/disk/by-uuid/'+m.spec.slice(5):m.spec.startsWith('LABEL=')?'/dev/disk/by-label/'+m.spec.slice(6):m.spec;
  const net=m.kind==='remote'||(m.opts||[]).includes('_netdev');
  const auto=(m.opts||[]).includes('x-systemd.automount');
  L.push(`# /etc/systemd/system/${name}.mount`,'[Unit]',`Description=${m.desc} at ${m.target}`);
  if(net) L.push('After=network-online.target','Wants=network-online.target');
  if(m.kind==='bind'){const src=containingMount(m.spec);if(src&&src.target!=='/') L.push(`RequiresMountsFor=${src.target}`)}
  if(m.kind==='zfs') L.push('After=zfs-import.target','Requires=zfs-import.target');
  L.push('','[Mount]',`What=${what}`,`Where=${m.target}`,`Type=${m.kind==='bind'?'none':m.fs}`);
  const o=(m.opts||[]).filter(x=>!x.startsWith('x-systemd.')&&x!=='_netdev');
  if(m.kind==='zfs') o.push('zfsutil');
  if(o.length) L.push(`Options=${o.join(',')}`);
  if(net) L.push('TimeoutSec=30');
  L.push('','[Install]',`WantedBy=${auto?'':net?'remote-fs.target':'local-fs.target'}`.replace(/=$/,'=  # started by the .automount unit'));
  if(auto){L.push('',`# /etc/systemd/system/${name}.automount`,'[Unit]',`Description=Automount ${m.target}`,'','[Automount]',`Where=${m.target}`,'TimeoutIdleSec=600','','[Install]',`WantedBy=${net?'remote-fs.target':'local-fs.target'}`)}
  return L.join('\n');
}
function genUnits(){ return collectMounts().filter(m=>m.kind!=='swap').map(unitFor).join('\n\n') }
const byId=d=>`/dev/disk/by-id/${d.bus.startsWith('NVMe')?'nvme':d.bus.startsWith('SAS')?'scsi':'ata'}-${d.model.split(' (')[0].replace(/\s+/g,'_')}_${d.serial}`;
function blueprint(){
  return {apiVersion:'storageforge/v1',kind:'StorageBlueprint',metadata:{host:S.host,generated:today(),identifiers:S.idMode},
    devices:S.disks.map(d=>({dev:'/dev/'+d.dev,model:d.model,serial:d.serial,bus:d.bus,media:d.media,tier:d.tier,sizeBytes:d.size,sector:{logical:d.lbs,physical:d.pbs},table:d.table,member:d.member,
      partitions:d.parts.map(p=>({id:p.id,num:p.num,uuid:p.uuid,startBytes:p.start,startMiB:+(p.start/MiB).toFixed(3),sizeBytes:p.size,fs:p.fs,label:p.label,mount:p.mount,options:p.opts,member:p.member,role:p.role,subvolumes:p.subvols}))})),
    pools:S.pools.map(p=>({name:p.name,type:p.type,level:p.level,tier:p.tier,ashift:p.ashift,fs:p.fs,mount:p.mount,encryption:p.encryption,members:poolMembers(p).data.map(x=>x.id),log:poolMembers(p).log.map(x=>x.id),cache:poolMembers(p).cache.map(x=>x.id),datasets:p.datasets,label:p.label,options:p.opts,vg:p.vg,lv:p.lv,levelSource:p.levelSource,usableBytes:Math.round(calcEngine(poolCalc(p)).usable)})),
    mounts:collectMounts().map(m=>({target:m.target,kind:m.kind,fs:m.fs,spec:m.spec,options:m.opts,tier:m.tier,source:m.dev})),
    remotes:S.remotes.map(r=>({...(r.raw||{}),id:r.id,capacity:r.capacity,name:r.name,protocol:r.proto,endpoint:r.endpoint,via:r.via,mount:r.mount,status:r.status,options:r.opts})),
    links:S.links.map(l=>({kind:l.kind,path:l.path,target:l.target,health:linkHealth(l).state,fromScan:l.fromScan||undefined})),
    exports:S.exports.map(e=>({...(e.raw||{}),protocol:e.proto,name:e.name,path:e.path,clients:e.clients,options:e.opts})),
    protection:S.protection.map(r=>{const m=collectMounts().find(x=>x.node===r.node)||{};return {node:r.node,dataset:r.name,path:m.target||null,tier:m.tier||null,ephemeral:!!r.ephemeral,sync:r.sync,snapshots:{enabled:r.snap.on,tool:r.snap.tool,policy:r.snap.policy,count:r.snap.count,overhead:r.snap.overhead},backup:r.backup,status:protStatus(r).t,...(r.deployed?{deployed:r.deployed,hand:r.hand}:{})}}),
    planner:{existing:S.existing||{},known:S.known||[]}};
}
function yamlScalar(v){ if(v===null||v===undefined) return 'null'; if(typeof v==='number'||typeof v==='boolean') return String(v); const s=String(v); return (/^[\w./@-]+$/.test(s)&&!/^(true|false|null|yes|no|\d.*)$/i.test(s))?s:JSON.stringify(s) }
function toYAML(v,ind=''){
  if(Array.isArray(v)){ if(!v.length) return ' []'; return v.map(x=>'\n'+ind+'- '+(x&&typeof x==='object'&&!Array.isArray(x)?toYAML(x,ind+'  ').replace(/^\n\s*/,''):Array.isArray(x)?toYAML(x,ind+'  '):yamlScalar(x))).join('') }
  if(v&&typeof v==='object'){ const ks=Object.keys(v).filter(k=>v[k]!==undefined); if(!ks.length) return ' {}'; return ks.map(k=>'\n'+ind+k+':'+(v[k]&&typeof v[k]==='object'?toYAML(v[k],ind+'  '):' '+yamlScalar(v[k]))).join('') }
  return ' '+yamlScalar(v);
}
function genASCII(){
  const L=[S.host];const M=collectMounts();
  const tree=(items,pre)=>items.forEach((it,i)=>{const last=i===items.length-1;L.push(pre+(last?'└── ':'├── ')+it.t);if(it.c) tree(it.c,pre+(last?'    ':'│   '))});
  const mountsAt=node=>M.filter(m=>m.node===node).map(m=>' → '+m.target).join('');
  const linksOn=t=>S.links.filter(l=>{const c=containingMount(l.target,M);return c&&c.target===t}).map(l=>({t:`${l.kind==='symlink'?'⇠':'⇇'} ${l.path} (${l.kind})`}));
  const items=[];
  ['fast','mass','remote'].forEach(tier=>{
    const c=[];
    S.disks.filter(d=>d.tier===tier).forEach(d=>{
      const dc=d.member?[{t:`whole disk → ${(poolBy(d.member)||{}).type==='lvm'?(poolBy(d.member).lv?'LVM RAID leg of '+lvPath(poolBy(d.member)):'LVM PV in '+d.member):'zpool '+d.member}`}]:d.parts.map(p=>{
        const pc=p.subvols&&p.subvols.length?p.subvols.map(s=>({t:`${s.name}${s.mount?' → '+s.mount:''}`,c:s.mount?linksOn(s.mount):null})):p.mount?linksOn(p.mount):null;
        return {t:`${p.id.replace(d.dev,'')}  ${(p.fs).padEnd(6)} ${fmtBin(p.size).padStart(10)}${p.member?` → ${p.member} (${p.role||'member'})`:p.mount&&MOUNTABLE.includes(p.fs)&&!(p.subvols&&p.subvols.length)?' → '+p.mount:''}`,c:pc&&pc.length?pc:null}});
      c.push({t:`${d.dev.padEnd(8)} ${d.model} [${d.bus}] ${fmtBin(d.size)}`,c:dc});
    });
    S.pools.filter(p=>p.tier===tier).forEach(p=>{const m=poolMembers(p);const r=calcEngine(poolCalc(p));
      const pc=[{t:`members: ${m.data.map(x=>x.id).join(' ')}`}];if(m.log.length) pc.push({t:'log: '+m.log.map(x=>x.id).join(' ')});if(m.cache.length) pc.push({t:'cache: '+m.cache.map(x=>x.id).join(' ')});
      if(p.type==='zfs'){ if(p.mount) pc.push({t:`${p.name} → ${p.mount}`}); (p.datasets||[]).forEach(ds=>{const lc=ds.mount?linksOn(ds.mount):[];pc.push({t:`${p.name}/${ds.name}${ds.mount?' → '+ds.mount:''}  [rs=${ds.recordsize} ${ds.compression}]`,c:lc.length?lc:null})}) }
      else pc.push({t:`${p.fs} → ${p.mount}`,c:linksOn(p.mount).length?linksOn(p.mount):null});
      c.push({t:`${p.name}  ${p.type} ${p.level}  usable ${fmtBin(r.usable)}`,c:pc})});
    if(tier==='remote') S.remotes.forEach(r=>{const lc=linksOn(r.mount);c.push({t:`${r.endpoint}  ${r.proto} via ${r.via} → ${r.mount} [${r.status}]`,c:lc.length?lc:null})});
    items.push({t:`[${tier.toUpperCase()} TIER]`,c});
  });
  tree(items,'');
  return L.join('\n');
}

/* ───────────── rendering ───────────── */
function nav(){
  const A=analyze();const crit=A.filter(a=>a.sev==='crit').length,warn=A.filter(a=>a.sev==='warn').length;
  const linkBad=S.links.filter(l=>linkHealth(l).state!=='ok').length;
  const protBad=S.protection.filter(r=>protStatus(r).k==='crit').length;
  const cnt={overview:crit?`<span class="cnt crit">${crit}</span>`:'',devices:`<span class="cnt">${S.disks.length}</span>`,mounts:`<span class="cnt">${collectMounts().filter(m=>m.kind!=='swap').length}</span>`,links:linkBad?`<span class="cnt crit">${linkBad}</span>`:`<span class="cnt">${S.links.length}</span>`,protection:protBad?`<span class="cnt crit">${protBad}</span>`:''};
  $('#nav').innerHTML=VIEWS.map(([k,t])=>`<button type="button" data-view="${k}" class="${UI.view===k?'on':''}">${t}${cnt[k]||''}</button>`).join('');
  $('#idmode').querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.id===S.idMode));
  $('#topchips').innerHTML=`<span class="pill ${crit?'crit':'ok'}">${crit} critical</span><span class="pill ${warn?'warn':'ok'}">${warn} warnings</span>`;
  $('#hostline').textContent=(DOC.host?(DOC.source==='scan'?'from scan · ':'design · '):'example · ')+S.host;
}
/* A render replaces the whole view, and whatever had focus goes with it: after a change the keyboard user was dropped on the page and had to tab in
   from the top (UX-18). So say which element had focus, and put focus on its twin in the new view, caret and all. */
const FOCUS_BOXES=['#nav','#view'];
const attrq=s=>String(s).replace(/["\\]/g,'\\$&');
function focusState(){
  const a=document.activeElement;if(!a||a===document.body) return null;
  const box=FOCUS_BOXES.find(b=>$(b).contains(a));if(!box) return null;
  const sel=a.id?'#'+CSS.escape(a.id):a.tagName.toLowerCase()+Object.entries(a.dataset).map(([k,x])=>`[data-${k.replace(/[A-Z]/g,m=>'-'+m.toLowerCase())}="${attrq(x)}"]`).join('');
  const st={box,sel,idx:Math.max(0,[...$(box).querySelectorAll(sel)].indexOf(a)),act:a.dataset.act};
  if(typeof a.selectionStart==='number'){ try{ st.start=a.selectionStart;st.end=a.selectionEnd }catch(e){} }
  return st;
}
function restoreFocus(st){
  if(!st) return;
  let same=[...$(st.box).querySelectorAll(st.sel)];
  if(!same.length&&st.act){ same=[...$(st.box).querySelectorAll(`[data-act="${attrq(st.act)}"]`)];st.idx=Math.min(st.idx,same.length-1) }   // it was removed (a deleted row): the next one of its kind
  const el=same[Math.min(st.idx,same.length-1)];if(!el) return;
  el.focus({preventScroll:true});
  if(st.start!=null&&typeof el.setSelectionRange==='function'){ try{ el.setSelectionRange(st.start,st.end) }catch(e){} }
}
let renderTimer=0;
function renderSoon(){ clearTimeout(renderTimer);renderTimer=setTimeout(render,0) }   // a change that came with Tab: let focus move on first, so the next field is the one that keeps it
function render(){
  const keep=focusState();
  nav();
  const v=VIEWS.find(x=>x[0]===UI.view);$('#vt').textContent=v[1];$('#vs').textContent=v[2];
  const fn={overview:vOverview,devices:vDevices,mounts:vMounts,links:vLinks,topology:vTopology,raid:vRaid,protection:vProtection,export:vExport}[UI.view];
  $('#view').innerHTML=fn();
  if(UI.view==='topology') requestAnimationFrame(drawEdges);
  setChain(null);
  restoreFocus(keep);
}
function setChain(id){
  const view=$('#view');view.querySelectorAll('.lit').forEach(x=>x.classList.remove('lit'));
  if(!id){view.classList.remove('chain-on');$('#chain').innerHTML='Hover any disk, partition, dataset, mount or link to trace its chain from physical device to target path.';return}
  const set=chainOf(id);view.classList.add('chain-on');
  view.querySelectorAll('[data-node]').forEach(x=>{if(set.has(x.dataset.node)) x.classList.add('lit')});
  view.querySelectorAll('path.edge').forEach(p=>{if(set.has(p.dataset.a)&&set.has(p.dataset.b)) p.classList.add('lit')});
  const groups={};[...set].forEach(n=>{const t=n.split(':')[0];(groups[t]=groups[t]||[]).push(n)});
  const parts=TORDER.filter(t=>groups[t]).map(t=>{const g=groups[t];const head=g.slice(0,3).map(n=>`<b>${esc(nodeLabel(n))}</b>`).join(', ');return g.length>3?`${head} <span>+${g.length-3}</span>`:head});
  $('#chain').innerHTML=parts.join('<span class="ar">→</span>');
}

/* overview */
function usableSummary(){
  let usable=0,parity=0,over=0;
  S.pools.forEach(p=>{const r=calcEngine(poolCalc(p));usable+=r.usable;parity+=r.parity;over+=r.overhead+r.waste});
  allParts().forEach(({p,d})=>{ if(d.tier==='remote'||p.member) return; if(MOUNTABLE.includes(p.fs)) usable+=p.size });
  return {usable,parity,over};
}
function vOverview(){
  const A=analyze();const crit=A.filter(a=>a.sev==='crit').length,warn=A.filter(a=>a.sev==='warn').length;
  const local=S.disks.filter(d=>d.tier!=='remote');const raw=sum(local.map(d=>d.size));
  const u=usableSummary();
  const P=S.protection.map(protStatus);const pOk=P.filter(x=>x.k==='ok').length,pW=P.filter(x=>x.k==='warn').length,pC=P.filter(x=>x.k==='crit').length,pM=P.filter(x=>x.k==='muted').length;
  const pct=(x,t)=>(t?x/t*100:0).toFixed(2)+'%';
  const tiles=`<div class="grid g4">
    <div class="panel kpi"><span class="eyebrow">Raw local capacity</span><span class="v">${fmtDec(raw,1)} <small>${fmtBin(raw,1)}</small></span><span class="s">${local.length} block devices · ${S.disks.filter(d=>d.tier==='remote').length} network LUN</span></div>
    <div class="panel kpi"><span class="eyebrow">Usable after redundancy</span><span class="v">${fmtDec(u.usable,1)} <small>${fmtBin(u.usable,1)}</small></span><span class="s">${fmtBin(u.parity,1)} parity/mirror · ${fmtBin(u.over,1)} overhead &amp; padding</span>
      <div class="kbar" title="usable / parity / overhead"><i style="width:${pct(u.usable,raw)};background:var(--accent)"></i><i style="width:${pct(u.parity,raw)};background:var(--mass)"></i><i style="width:${pct(u.over,raw)};background:var(--remote)"></i></div></div>
    <div class="panel kpi"><span class="eyebrow">3-2-1 protection</span><span class="v">${pOk}<small>/ ${P.length-pM} datasets fully protected</small></span><span class="s"><span class="dot ok"></span>${pOk} protected <span class="dot warn"></span>${pW} local only <span class="dot crit"></span>${pC} critical</span></div>
    <div class="panel kpi"><span class="eyebrow">Guardrails</span><span class="v" style="color:var(${crit?'--crit':'--ok'})">${crit}<small>critical · ${warn} warnings</small></span><span class="s">${S.links.length} links · ${collectMounts().length} mounts checked</span></div>
  </div>`;
  const alerts=`<section class="panel"><div class="ph"><h2>Guardrail alerts</h2><span class="sub">Select an alert to open the view where it is fixed</span></div>
    <div class="alerts">${A.length?A.map(a=>`<div class="alert ${a.sev}" data-act="goto" data-v="${a.view}" ${a.node?`data-node="${esc(a.node)}" data-sel="${esc(a.node)}"`:''} tabindex="0" role="button"><span class="bar"></span><div><b>${esc(a.title)}</b><p>${esc(a.detail)}</p></div><span class="go">${esc(VIEWS.find(v=>v[0]===a.view)[1])} →</span></div>`).join(''):'<div class="pb empty">No issues found. Every mount resolves and every dataset has a protected copy.</div>'}</div></section>`;
  const tierCard=(tier,title,items)=>`<section class="panel tier ${tier}"><div class="ph"><h3>${title}</h3><span class="sub">${items.length} items</span></div><div class="pb" style="padding-top:4px;padding-bottom:4px">${items.join('')}</div></section>`;
  const it=(node,n,r,z)=>`<div class="titem" data-node="${esc(node)}"><span class="n">${n}</span><span class="r">${r}</span><span class="z">${z}</span></div>`;
  const partRole=p=>p.member?(p.role==='log'?`SLOG / ZIL for ${p.member}`:p.role==='cache'?`L2ARC read cache for ${p.member}`:`member of ${p.member}`):p.subvols&&p.subvols.length?`btrfs · ${p.subvols.filter(s=>s.mount).map(s=>s.mount).join(' ')}`:`${p.fs}${p.mount?' · '+p.mount:''}`;
  const fast=allParts().filter(x=>x.d.tier==='fast').map(({p,d})=>it('part:'+p.id,'/dev/'+p.id,esc(partRole(p))+` <span class="chip">${esc(d.bus.split(' ').slice(0,3).join(' '))}</span>`,fmtBin(p.size)));
  const mass=[...S.pools.filter(p=>p.tier==='mass').map(p=>{const r=calcEngine(poolCalc(p));const m=poolMembers(p);return it('pool:'+p.name,`${esc(p.name)} · ${esc(p.type)} ${esc(p.level)}`,`${m.data.length}× ${esc(m.data[0]?m.data[0].disk.model.split(' (')[0]:'')} · tolerates ${r.tol}`,fmtBin(r.usable)+'<br><span class="muted">usable</span>')}),
    ...allParts().filter(x=>x.d.tier==='mass'&&!x.p.member).map(({p,d})=>it('part:'+p.id,'/dev/'+p.id,esc(partRole(p))+' · no redundancy',fmtBin(p.size)))];
  const remote=[...allParts().filter(x=>x.d.tier==='remote').map(({p,d})=>it('part:'+p.id,'/dev/'+p.id,`${esc(d.bus)} · ${esc(partRole(p))}`,fmtBin(p.size))),
    ...S.remotes.map(r=>it('rem:'+r.id,`<span class="dot ${r.status==='connected'?'ok':'crit'}"></span>${esc(r.name)}`,`${esc(r.proto)} via ${esc(r.via)} → ${esc(r.mount)}`,r.capacity?fmtDec(r.capacity,0):'metered'))];
  return tiles+activityPanel()+`<div class="grid" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);align-items:start" id="ovgrid">${alerts}<div class="stack">${tierCard('fast','Fast local tier',fast)}${tierCard('mass','Mass local tier',mass)}${tierCard('remote','Remote / mesh targets',remote)}</div></div>
  `;
}

/* what the rest of StorageForge holds for this host: staged changes, moves, shares, deployed jobs, drift, access */
function activityPanel(){
  if(!DOC.host||!DOC.signedIn) return '';
  const a=DOC.activity;
  const head=`<div class="ph"><h2>Across StorageForge</h2><span class="sub">Staged, deployed and scanned on ${esc(DOC.host)}</span></div>`;
  if(!a) return `<section class="panel">${head}<div class="pb muted">Loading…</div></section>`;
  const it=(tab,n,r,z)=>`<div class="titem"><span class="n"><a href="${esc(appLink(tab))}">${n} →</a></span><span class="r">${r}</span><span class="z">${z}</span></div>`;
  const cnt=(n,k)=>`<span class="pill ${n?k:'muted'}">${n}</span>`;
  const pl=(n,w)=>`${n} ${w}${n===1?'':'s'}`;
  const JOB={ok:'ok',paused:'muted','never-ran':'warn',stale:'crit',failed:'crit',removed:'muted'};
  const sh=a.shares;
  const rows=[
    it('changes','Staged changes',a.changes.length?a.changes.map(p=>`${esc(p.name)} · ${pl(p.tasks,'task')} (${esc(p.types.join(', '))})`).join('<br>'):'Nothing staged. Folder, btrfs, mount and drive changes are staged from the topology.',cnt(sum(a.changes.map(p=>p.tasks)),'info')),
    it('moves','Data moves',a.moves.length?a.moves.map(p=>`${esc(p.name)} · ${pl(p.steps,'step')}`).join('<br>'):'No move plans copy to or from this host.',cnt(a.moves.length,'info')),
    it('deploy','Shares',sh?`${pl(sh.exports,'share')} in the design${sh.crit?` · ${sh.crit} critical`:''}${sh.warn?` · ${pl(sh.warn,'warning')}`:''}`:'Scan the host to check its shares against the index.',cnt(sh?sh.exports:0,sh&&sh.crit?'crit':sh&&sh.warn?'warn':'ok')),
    it('deploy','Deployed jobs',a.jobs.length?a.jobs.map(j=>`${esc(j.name)} · ${esc(j.method)} · <span class="st ${JOB[j.state]||'muted'}">${esc(j.state)}</span>`).join('<br>'):'No backup, sync or snapshot jobs run from or for this host.',cnt(a.jobs.length,a.jobs.some(j=>JOB[j.state]==='crit')?'crit':'ok')),
    it('deploy','Drift',a.drift.length?a.drift.slice(0,4).map(d=>esc(d.text)).join('<br>')+(a.drift.length>4?`<br>+${a.drift.length-4} more`:''):'Deployed files, units and fstab lines match what StorageForge wrote.',cnt(a.drift.length,'warn')),
    it('access','Unreadable folders',a.unreadable==null?'Not scanned yet.':a.unreadable?`The last scan could not open ${pl(a.unreadable,'folder')}. Read-only scan access fixes that without scanning as root.`:'The last scan read every folder.',cnt(a.unreadable||0,'warn'))];
  return `<section class="panel">${head}<div class="pb" style="padding-top:4px;padding-bottom:4px">${rows.join('')}</div></section>`;
}

/* devices */
function segHTML(d,p){
  const sel=UI.sel&&UI.sel.type==='part'&&UI.sel.id===p.id;
  const sub=p.member?`${p.role==='data'||!p.role?'member':p.role} → ${p.member}`:p.subvols&&p.subvols.length?`${p.subvols.length} subvols`:p.mount||'not mounted';
  return `<button type="button" class="seg fs-${esc(p.fs)} ${sel?'sel':''}" style="flex-grow:${p.size/d.size}" data-node="part:${esc(p.id)}" data-act="sel" data-type="part" data-id="${esc(p.id)}" title="/dev/${esc(p.id)} · ${esc(p.fs)} · ${fmtBin(p.size)}"><b>p${p.num} ${esc(p.label||'')}</b><span>${esc(p.fs)} · ${fmtBin(p.size,1)}</span><span>${esc(sub)}</span></button>`;
}
function diskHTML(d){
  const sel=UI.sel&&UI.sel.type==='disk'&&UI.sel.id===d.dev;
  let segs='';
  if(d.member){const mp=poolBy(d.member)||{};const lvm=mp.type==='lvm';segs=`<button type="button" class="seg ${lvm?'fs-linux_raid_member':'fs-zfs_member'}" style="flex-grow:1" data-node="disk:${esc(d.dev)}" data-act="sel" data-type="pool" data-id="${esc(d.member)}"><b>whole disk · ${lvm?(mp.lv?'LVM RAID leg':'LVM PV'):'zfs member'}</b><span>→ ${lvm?(mp.lv?`${esc(mp.vg)}/${esc(mp.lv)} · ${esc(mp.level)} · PV on the bare disk`:`volume group ${esc(mp.vg)}`):`${esc(d.member)} · partitions p1/p9 created by zpool`}</span></button>`}
  else{
    let cur=0;const parts=d.parts.slice().sort((a,b)=>a.start-b.start);const limit=d.table==='mbr'?Math.min(d.size,2*TiB):d.size;
    parts.forEach(p=>{ if(p.start-cur>=64*MiB) segs+=`<div class="seg free" style="flex-grow:${(p.start-cur)/d.size}"><b>free</b><span>${fmtBin(p.start-cur,1)}</span></div>`; segs+=segHTML(d,p); cur=p.start+p.size });
    if(limit-cur>=64*MiB) segs+=`<div class="seg free" style="flex-grow:${(limit-cur)/d.size}"><b>unallocated</b><span>${fmtBin(limit-cur,1)}</span></div>`;
    if(d.table==='mbr'&&d.size>2*TiB) segs+=`<div class="seg dead" style="flex-grow:${(d.size-2*TiB)/d.size}"><b>beyond MBR limit</b><span>${fmtBin(d.size-2*TiB,1)} unaddressable</span></div>`;
  }
  const sect=d.lbs===d.pbs?(d.pbs===4096?'4Kn':'512n'):'512e';
  return `<article class="disk ${esc(d.tier)} ${sel?'sel':''}" data-node="disk:${esc(d.dev)}" data-act="sel" data-type="disk" data-id="${esc(d.dev)}">
    <div class="dh"><span class="dev">/dev/${esc(d.dev)}</span><span class="chip t-${esc(d.tier)}">${esc(d.bus)}</span><span class="chip">${d.table.toUpperCase()}</span><span class="chip">${sect} · ${d.lbs}/${d.pbs}</span>${d.os?'<span class="chip">boot</span>':''}<span class="sz">${both(d.size)}</span></div>
    <div class="dmeta">${esc(d.model)} · SN ${esc(d.serial)}</div>
    <div class="pbar">${segs}</div></article>`;
}
function poolHTML(p){
  const sel=UI.sel&&UI.sel.type==='pool'&&UI.sel.id===p.name;const m=poolMembers(p);const r=calcEngine(poolCalc(p));
  const rows=p.type==='lvm'&&!p.lv?(p.datasets||[]).map(ds=>`<div class="dsrow" data-node="ds:${esc(p.name)}/${esc(ds.name)}"><span>${esc(p.vg)}/${esc(ds.name)}</span><span class="muted">${esc(ds.mount||(ds.fs==='swap'?'[swap]':'—'))}</span><span class="muted">${esc(ds.fs||'no fs')} · ${fmtBin(ds.sizeBytes||0,1)}</span></div>`).join(''):p.type==='zfs'?(p.datasets||[]).map(ds=>`<div class="dsrow" data-node="ds:${esc(p.name)}/${esc(ds.name)}"><span>${esc(p.name)}/${esc(ds.name)}</span><span class="muted">${esc(ds.mount||'—')}</span><span class="muted">rs=${esc(ds.recordsize)} ${esc(ds.compression)}${ds.sync!=='standard'?' sync='+esc(ds.sync):''}</span></div>`).join(''):`<div class="dsrow"><span>${esc(p.fs)} · ${esc(p.label)}</span><span class="muted">${esc(p.mount)}</span><span class="muted">${esc((p.opts||[]).join(','))}</span></div>`;
  return `<article class="pool ${sel?'sel':''}" data-node="pool:${esc(p.name)}" data-act="sel" data-type="pool" data-id="${esc(p.name)}">
    <div class="dh"><span class="dev">${esc(p.name)}</span><span class="chip t-${esc(p.tier)}">${p.type==='lvm'&&!p.lv?'LVM volume group':(POOL_KIND[p.type]||'mdadm')+' '+esc(p.level)}</span>${p.lv?`<span class="chip">${esc(p.vg)}/${esc(p.lv)}</span>`:''}${p.levelSource&&p.levelSource.startsWith('inferred')?`<span class="chip" title="${esc(p.levelSource)}">level inferred</span>`:''}${p.type==='zfs'?`<span class="chip">ashift=${p.ashift}</span><span class="chip">${p.encryption==='off'?'unencrypted':esc(p.encryption)}</span>`:''}<span class="sz">${fmtBin(r.usable)} usable · tolerates ${r.tol}</span></div>
    <div class="members">${m.data.map(x=>`<span class="chip" data-node="${x.whole?'disk:'+x.id:'part:'+x.id}">${esc(x.id)}</span>`).join('')}${m.log.map(x=>`<span class="chip t-fast" data-node="part:${x.id}">log ${esc(x.id)}</span>`).join('')}${m.cache.map(x=>`<span class="chip t-fast" data-node="part:${x.id}">cache ${esc(x.id)}</span>`).join('')}</div>
    <div>${rows}</div></article>`;
}
function remoteHTML(r){
  const sel=UI.sel&&UI.sel.type==='rem'&&UI.sel.id===r.id;
  return `<article class="pool ${sel?'sel':''}" data-node="rem:${esc(r.id)}" data-act="sel" data-type="rem" data-id="${esc(r.id)}">
    <div class="dh"><span class="dot ${r.status==='connected'?'ok':'crit'}"></span><span class="dev">${esc(r.name)}</span><span class="chip t-remote">${esc(r.proto)}</span><span class="chip">${esc(r.via)}</span><span class="sz">${r.capacity?fmtDec(r.capacity,0):'metered'}</span></div>
    <div class="dsrow" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr)"><span>${esc(r.endpoint)}</span><span class="muted">→ ${esc(r.mount)}</span></div></article>`;
}
function optChips(fs,opts,scope){
  const cat=[...(OPTS[fs]||[])];(opts||[]).forEach(o=>{if(!cat.includes(o)&&!o.startsWith('subvol')) cat.push(o)});
  return `<div class="chips">${cat.map(o=>`<button type="button" class="opt ${(opts||[]).includes(o)?'on':''} ${DANGER_OPTS.includes(o)?'danger':''}" data-act="opt" data-scope="${scope}" data-opt="${esc(o)}">${esc(o)}</button>`).join('')}</div>
    <div class="row"><input type="text" class="mono" id="customopt-${scope}" placeholder="add option, e.g. x-systemd.device-timeout=10s" data-f="customopt" data-scope="${scope}" aria-label="Custom mount option"></div>`;
}
function inspector(){
  const s=UI.sel;
  if(!s) return `<div class="ph"><h2>Inspector</h2></div><div class="pb"><p class="muted" style="margin:0">Select a partition, disk, pool or remote target to edit filesystem, mount point and options. Changes regenerate fstab, units and scripts immediately.</p>
    <div class="legend">${['vfat','ext4','xfs','btrfs','f2fs','zfs_member','linux_raid_member','swap'].map(f=>`<span class="fs-${f}"><i></i>${f}</span>`).join('')}</div></div>`;
  if(s.type==='part'){
    const x=findPart(s.id);if(!x) return '';const {p,d}=x;
    const aligned=p.start%MiB===0;const member=!!p.member;
    const mounts=collectMounts().filter(m=>m.node==='part:'+p.id||m.node.startsWith(`sv:${p.id}/`));
    return `<div class="ph"><h2>/dev/${esc(p.id)}</h2><span class="sub">${esc(d.model)}</span></div><div class="pb">
      <dl class="kv"><dt>Start</dt><dd>${p.start/512}s · ${(p.start/MiB).toFixed(p.start%MiB?3:0)} MiB</dd><dt>Size</dt><dd>${both(p.size)}</dd><dt>Sectors</dt><dd>${Math.round(p.size/d.lbs).toLocaleString()} × ${d.lbs} B</dd><dt>Spec</dt><dd>${esc(specFor(p))}</dd></dl>
      <div class="note ${aligned?'ok':'crit'}">${aligned?`Aligned to 1 MiB · ${d.pbs}-byte physical sectors respected.`:`Misaligned: starts at sector ${p.start/512}, not a multiple of 2048. Recreate at 1 MiB.`}</div>
      <div class="fields">
        <label class="f">Label<input type="text" id="i-label" value="${esc(p.label||'')}" data-f="label"></label>
        <label class="f">Filesystem<select id="i-fs" data-f="fs" ${member?'disabled':''}>${(member?[p.fs]:FS_LIST).map(f=>`<option ${f===p.fs?'selected':''}>${f}</option>`).join('')}</select></label>
        ${member?`<div class="note full">Member of <b>${esc(p.member)}</b> as ${esc(p.role||'data')}. Edit the pool to change it.</div>`:''}
        ${!member&&MOUNTABLE.includes(p.fs)&&!(p.fs==='btrfs'&&p.subvols&&p.subvols.length)?`<label class="f full">Mount point<input type="text" class="mono" id="i-mount" value="${esc(p.mount||'')}" data-f="mount" placeholder="/mnt/…"></label>`:''}
      </div>
      ${!member&&OPTS[p.fs]?`<div><div class="eyebrow" style="margin-bottom:6px">Mount options</div>${optChips(p.fs,p.opts,'part')}</div>`:''}
      ${p.fs==='btrfs'?`<div><div class="eyebrow" style="margin-bottom:6px">Subvolumes</div>${(p.subvols||[]).map((sv,i)=>`<div class="row" data-node="sv:${esc(p.id)}/${esc(sv.name)}" style="margin-bottom:5px"><code style="min-width:84px">${esc(sv.name)}</code><input type="text" class="mono" id="i-sv-${i}" value="${esc(sv.mount||'')}" data-f="svmount" data-i="${i}" aria-label="Mount point for ${esc(sv.name)}"><button type="button" class="xbtn" data-act="delsv" data-i="${i}" aria-label="Remove subvolume">×</button></div>`).join('')}
        <div class="row"><input type="text" class="mono" id="i-newsv" placeholder="@docker" data-f="newsv" aria-label="New subvolume name"><span class="muted" style="font-size:11.5px">Enter to add</span></div></div>`:''}
      ${mounts.length?`<div class="eyebrow">fstab preview</div><pre class="code panel" style="max-height:200px">${esc(mounts.filter(m=>m.kind!=='zfs').map(m=>[m.spec,m.target,m.fs,(m.opts.length?m.opts:['defaults']).join(','),0,passFor(m)].join('  ')).join('\n'))}</pre>`:''}
    </div>`;
  }
  if(s.type==='disk'){
    const d=diskBy(s.id);
    return `<div class="ph"><h2>/dev/${esc(d.dev)}</h2><span class="sub">${esc(d.bus)}</span></div><div class="pb">
      <dl class="kv"><dt>Model</dt><dd>${esc(d.model)}</dd><dt>Serial</dt><dd>${esc(d.serial)}</dd><dt>Capacity</dt><dd>${d.size.toLocaleString()} B<br>${both(d.size)}</dd><dt>Sectors</dt><dd>logical ${d.lbs} · physical ${d.pbs}</dd><dt>by-id</dt><dd>${esc(byId(d))}</dd></dl>
      <div class="fields"><label class="f">Partition table<select id="i-table" data-f="table" ${d.member?'disabled':''}><option ${d.table==='gpt'?'selected':''} value="gpt">GPT</option><option ${d.table==='mbr'?'selected':''} value="mbr">MBR (msdos)</option></select></label>
      <label class="f">Tier<select id="i-tier" data-f="tier">${['fast','mass','remote'].map(t=>`<option ${t===d.tier?'selected':''}>${t}</option>`).join('')}</select></label></div>
      ${d.table==='mbr'&&d.size>2*TiB?`<div class="note warn">MBR caps addressable space at 2 TiB. Switch to GPT to reclaim ${fmtBin(d.size-2*TiB)}.</div>`:''}
      <div class="note">Decimal ${fmtDec(d.size,3)} on the label is ${fmtBin(d.size,3)} in the binary units <code>lsblk</code>, <code>df -h</code> and ZFS report. The gap is ${(100-d.size/(d.size/1e12*TiB)*100).toFixed(1)}%.</div></div>`;
  }
  if(s.type==='pool'){
    const p=poolBy(s.id);if(!p) return '';const r=calcEngine(poolCalc(p));
    return `<div class="ph"><h2>${esc(p.name)}</h2><span class="sub">${p.type==='zfs'?'OpenZFS pool':p.type==='lvm'&&!p.lv?'LVM volume group':(POOL_KIND[p.type]||'mdadm')+' array'}${p.levelSource?' · level '+esc(p.levelSource):''}</span></div><div class="pb">
      <div class="fields">
        <label class="f">Level<select id="i-level" data-f="level">${(p.type==='lvm'&&!p.lv?['linear']:p.type==='zfs'?['stripe','mirror','raidz1','raidz2','raidz3']:['raid0','raid1','raid5','raid6','raid10']).map(l=>`<option ${l===p.level?'selected':''}>${l}</option>`).join('')}</select></label>
        ${p.type==='zfs'?`<label class="f">ashift<select id="i-ashift" data-f="ashift">${[9,12,13].map(a=>`<option value="${a}" ${a==p.ashift?'selected':''}>${a} (${2**a} B)</option>`).join('')}</select></label>
          <label class="f">Encryption<select id="i-enc" data-f="encryption">${['aes-256-gcm','aes-128-gcm','off'].map(a=>`<option ${a===p.encryption?'selected':''}>${a}</option>`).join('')}</select></label>
          <label class="f">Root mountpoint<input type="text" class="mono" id="i-pmount" value="${esc(p.mount||'')}" data-f="pmount"></label>`
        :`<label class="f">Filesystem<select id="i-pfs" data-f="pfs">${['ext4','xfs','btrfs'].map(a=>`<option ${a===p.fs?'selected':''}>${a}</option>`).join('')}</select></label><label class="f full">Mount point<input type="text" class="mono" id="i-pmount" value="${esc(p.mount||'')}" data-f="pmount"></label>`}
      </div>
      <dl class="kv"><dt>Usable</dt><dd>${both(r.usable)}</dd><dt>Parity</dt><dd>${fmtBin(r.parity)}</dd><dt>Tolerance</dt><dd>${esc(r.tolNote)}</dd><dt>Resilver</dt><dd>~${r.rebuildH.toFixed(1)} h at 180 MB/s, 70% full</dd></dl>
      ${r.notes.map(n=>`<div class="note ${n[0]==='info'?'':n[0]}">${esc(n[1])}</div>`).join('')}
      ${p.type==='zfs'?`<div><div class="eyebrow" style="margin-bottom:6px">Datasets</div><div class="tw"><table><thead><tr><th>Name</th><th>mountpoint</th><th>recordsize</th><th>compress</th><th>sync</th></tr></thead><tbody>${(p.datasets||[]).map((ds,i)=>`<tr data-node="ds:${esc(p.name)}/${esc(ds.name)}"><td class="mono">${esc(ds.name)}</td><td><input type="text" class="mono" id="i-ds-m-${i}" value="${esc(ds.mount||'')}" data-f="dsmount" data-i="${i}" style="width:100%;min-width:140px" aria-label="mountpoint"></td><td><select id="i-ds-r-${i}" data-f="dsrs" data-i="${i}" aria-label="recordsize">${['16K','64K','128K','1M'].map(v=>`<option ${v===ds.recordsize?'selected':''}>${v}</option>`).join('')}</select></td><td><select id="i-ds-c-${i}" data-f="dscomp" data-i="${i}" aria-label="compression">${['lz4','zstd','zstd-3','off'].map(v=>`<option ${v===ds.compression?'selected':''}>${v}</option>`).join('')}</select></td><td><select id="i-ds-s-${i}" data-f="dssync" data-i="${i}" aria-label="sync">${['standard','always','disabled'].map(v=>`<option ${v===ds.sync?'selected':''}>${v}</option>`).join('')}</select></td></tr>`).join('')}</tbody></table></div>
        <div class="row" style="margin-top:8px"><input type="text" class="mono" id="i-newds" placeholder="new dataset name, e.g. docker" data-f="newds" aria-label="New dataset name"><span class="muted" style="font-size:11.5px">Enter to add</span></div></div>`:`<div><div class="eyebrow" style="margin-bottom:6px">Mount options</div>${optChips(p.fs,p.opts,'pool')}</div>`}
    </div>`;
  }
  if(s.type==='rem'){
    const r=remoteBy(s.id);
    return `<div class="ph"><h2>${esc(r.name)}</h2><span class="sub">${esc(r.proto)} via ${esc(r.via)}</span></div><div class="pb">
      <dl class="kv"><dt>Endpoint</dt><dd>${esc(r.endpoint)}</dd><dt>fstab type</dt><dd>${remoteFs(r)}</dd></dl>
      <div class="fields"><label class="f">Link state<select id="i-rstatus" data-f="rstatus"><option value="connected" ${r.status==='connected'?'selected':''}>Connected</option><option value="disconnected" ${r.status!=='connected'?'selected':''}>Disconnected</option></select></label>
      <label class="f">Mount point<input type="text" class="mono" id="i-rmount" value="${esc(r.mount)}" data-f="rmount"></label></div>
      <div><div class="eyebrow" style="margin-bottom:6px">Mount options</div>${optChips('net',r.opts,'rem')}</div>
      <div class="note">Network mounts use <code>_netdev</code> and <code>x-systemd.automount</code> so boot does not wait on the ${esc(r.via)} tunnel.</div></div>`;
  }
  return '';
}
function vDevices(){
  const tiers=[['fast','Fast local tier'],['mass','Mass local tier'],['remote','Network block devices']];
  return `<div class="split"><div class="stack" style="gap:22px">
    ${tiers.map(([t,h])=>{const ds=S.disks.filter(d=>d.tier===t);return ds.length?`<section class="stack"><div class="sec-h"><h2>${h}</h2><span class="muted" style="font-size:12px">${ds.length} device${ds.length>1?'s':''} · ${both(sum(ds.map(d=>d.size)))}</span></div>${ds.map(diskHTML).join('')}</section>`:''}).join('')}
    <section class="stack"><div class="sec-h"><h2>Pools &amp; arrays</h2></div><div class="grid g2">${S.pools.map(poolHTML).join('')}</div></section>
    <section class="stack"><div class="sec-h"><h2>Remote / mesh targets</h2></div><div class="grid g2">${S.remotes.map(remoteHTML).join('')}</div></section>
  </div><aside class="panel insp">${inspector()}</aside></div>`;
}

/* mounts */
function vMounts(){
  const M=collectMounts().filter(m=>m.kind!=='swap');const A=analyze();
  const dup={};M.forEach(m=>dup[m.target]=(dup[m.target]||0)+1);
  const parentOf=m=>M.filter(x=>x!==m&&x.target!==m.target&&isUnder(m.target,x.target)).sort((a,b)=>b.target.length-a.target.length)[0];
  const kids=new Map();const roots=[];
  M.forEach(m=>{const p=parentOf(m);if(p){if(!kids.has(p))kids.set(p,[]);kids.get(p).push(m)}else roots.push(m)});
  const flags=m=>{const f=[];if(dup[m.target]>1)f.push('<span class="pill crit">duplicate</span>');
    if(m.kind==='bind'){const h=linkHealth(m.link);if(h.state!=='ok')f.push(`<span class="pill ${h.state}">${h.state==='warn'?'non-empty':'broken'}</span>`)}
    else if(S.existing[m.target]) f.push('<span class="pill warn">non-empty</span>');
    if(m.kind==='remote'&&m.remote.status!=='connected') f.push('<span class="pill crit">offline</span>');
    return f.join('')};
  const rows=[];
  const walk=(m,d)=>{const p=parentOf(m);const rel=p&&p.target!=='/'?m.target.slice(p.target.length):m.target;const head=p&&p.target!=='/'?`<em>${esc(p.target)}</em>${esc(rel)}`:esc(m.target);
    rows.push(`<div class="trow ${UI.mountSel===m.target?'sel':''}" style="--d:${d}" data-node="${esc(m.node)}" data-act="msel" data-t="${esc(m.target)}" tabindex="0" role="button"><span class="p">${head}</span><span class="s">${esc(m.spec)}${m.kind==='subvol'?'':''} · ${esc(m.opts.join(',')||'defaults')}</span><span class="c"><span class="chip t-${esc(m.tier)}">${esc(m.kind==='bind'?'bind':m.fs)}</span>${flags(m)}</span></div>`);
    (kids.get(m)||[]).sort((a,b)=>a.target.localeCompare(b.target)).forEach(k=>walk(k,d+1))};
  roots.sort((a,b)=>a.target.localeCompare(b.target)).forEach(r=>walk(r,0));
  const sel=M.find(m=>m.target===UI.mountSel)||M[0];
  const conflicts=A.filter(a=>a.view==='mounts');
  const code=UI.mountTab==='fstab'?genFstab():sel?unitFor(sel):'';
  return `${conflicts.length?`<div class="stack">${conflicts.map(a=>`<div class="note ${a.sev}"><b>${esc(a.title)}.</b> ${esc(a.detail)}</div>`).join('')}</div>`:`<div class="note ok">No duplicate mount points, nested network mounts or mounts over non-empty directories.</div>`}
  <div class="grid g2" style="align-items:start">
    <section class="panel"><div class="ph"><h2>Mount hierarchy</h2><span class="sub">${M.length} mount points · select one for its unit</span></div><div class="tree">${rows.join('')}</div></section>
    <section class="panel"><div class="ph"><div class="tabs" role="tablist"><button type="button" role="tab" class="${UI.mountTab==='fstab'?'on':''}" data-act="mtab" data-t="fstab">/etc/fstab</button><button type="button" role="tab" class="${UI.mountTab==='unit'?'on':''}" data-act="mtab" data-t="unit">systemd unit${sel?' · '+esc(sdEscape(sel.target))+'.mount':''}</button></div><button type="button" class="btn sm" data-act="copy" data-src="mcode">Copy</button></div><pre class="code" id="mcode">${hl(code)}</pre></section>
  </div>`;
}
function hl(s){return esc(s).split('\n').map(l=>/^\s*#/.test(l)?`<span class="c">${l}</span>`:/^\[(Unit|Mount|Install|Automount)\]$/.test(l)?`<span class="k">${l}</span>`:l).join('\n')}

/* links */
const PRESETS=[
  {id:'appstate',t:'App state → fast NVMe',d:'Keep databases and caches on the scratch NVMe while services see their usual paths.',links:[{kind:'bind',path:'/var/lib/postgresql',target:'/mnt/fast_scratch/postgresql'},{kind:'symlink',path:'/var/cache/app',target:'/mnt/fast_scratch/cache/app'}]},
  {id:'logs',t:'Logs → burst buffer',d:'Send chatty application logs to the F2FS burst partition so they stop wearing the root SSD.',links:[{kind:'bind',path:'/var/log/app',target:'/mnt/burst/logs/app'}]},
  {id:'raw',t:'RAW archive → cold storage',d:'Move older photo RAWs to the mdadm cold array. Lightroom and darktable keep their library paths through symlinks.',links:[{kind:'symlink',path:'/home/ops/Pictures/RAW-2018',target:'/mnt/cold/photo-archive/2018'},{kind:'symlink',path:'/home/ops/Pictures/RAW-2019',target:'/mnt/cold/photo-archive/2019'}]},
  {id:'vm',t:'VM images → iSCSI LUN',d:'Point libvirt at the network LUN; mount ordering waits for iscsid.',links:[{kind:'bind',path:'/var/lib/libvirt/images',target:'/mnt/iscsi_vm/libvirt'}]}
];
function vLinks(){
  const M=collectMounts();
  const rows=S.links.map(l=>{const h=linkHealth(l,M);const m=h.m||containingMount(l.target,M);
    return `<tr data-node="link:${esc(l.id)}"><td><span class="kind ${esc(l.kind)}">${esc(l.kind)}</span></td><td class="lk">${esc(l.path)}</td><td class="arrow">${l.kind==='bind'?'⇇':l.kind==='hardlink'?'⇔':'→'}</td><td class="lk">${esc(l.target)}</td>
      <td class="lk muted">${m?esc(m.target)+'<br>'+esc(m.dev):'—'}</td><td><span class="pill ${h.state}">${h.state==='ok'?'healthy':h.state==='warn'?'warning':'broken'}</span><div class="why">${esc(h.msg)}</div></td><td><button type="button" class="xbtn" data-act="dellink" data-id="${esc(l.id)}" aria-label="Remove link">×</button></td></tr>`}).join('');
  const st=stages();
  const svc=S.links.filter(l=>SERVICE_HINT[l.path]).map(l=>{const src=containingMount(l.target,M);const svcName=SERVICE_HINT[l.path];return `# /etc/systemd/system/${svcName}.d/storageforge.conf\n[Unit]\nRequiresMountsFor=${l.path}${src&&src.target!=='/'?' '+src.target:''}`});
  return `<section class="stack"><div class="sec-h"><h2>Scenario presets</h2><span class="muted" style="font-size:12px">Adds links to the blueprint; health checks run immediately</span></div>
    <div class="grid g4">${PRESETS.map(p=>{const have=p.links.every(x=>S.links.some(l=>l.path===x.path));return `<div class="preset"><h3>${esc(p.t)}</h3><p>${esc(p.d)}</p><ul>${p.links.map(x=>`<li>${x.kind==='bind'?'bind':'ln -s'} ${esc(x.target)} → ${esc(x.path)}</li>`).join('')}</ul><button type="button" class="btn sm ${have?'':'pri'}" data-act="preset" data-id="${p.id}" ${have?'disabled':''}>${have?'Applied':'Apply preset'}</button></div>`}).join('')}</div></section>
  <section class="panel"><div class="ph"><h2>Link map</h2><span class="sub">path → target → backing filesystem → device</span></div>
    <div class="pb" style="border-bottom:1px solid var(--line)"><form class="row" id="addlink"><select id="nl-kind" aria-label="Link kind"><option value="symlink">symlink</option><option value="bind">bind mount</option><option value="hardlink">hard link</option></select><input type="text" class="mono" id="nl-path" placeholder="link path, e.g. /var/www" aria-label="Link path" required><span class="arrow">→</span><input type="text" class="mono" id="nl-target" placeholder="target, e.g. /mnt/fast_scratch/www" aria-label="Target" required><button class="btn pri" type="submit">Add link</button></form></div>
    <div class="tw"><table><thead><tr><th>Kind</th><th>Path</th><th></th><th>Target</th><th>Backing mount</th><th>Health</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan="7" class="empty">No links yet. Apply a preset or add one above.</td></tr>'}</tbody></table></div></section>
  <section class="panel"><div class="ph"><h2>Boot dependency order</h2><span class="sub">Each stage waits for the mounts it depends on</span></div><div class="pb"><div class="stages">${st.map((g,i)=>`<div class="stage"><h3>Stage ${i}${i===0?' · local-fs-pre':''}</h3>${g.map(({m,deps})=>`<div class="m" data-node="${esc(m.node)}">${esc(m.target)}<small>${m.kind==='bind'?'bind ← '+esc(m.spec):esc(m.kind==='remote'?m.remote.proto+' · after network-online':m.desc)}${deps.length?' · after '+deps.map(x=>esc(x.target)).join(', '):''}</small></div>`).join('')}</div>`).join('')}
    <div class="stage"><h3>Services</h3>${S.links.filter(l=>l.kind!=='bind').map(l=>`<div class="m" data-node="link:${esc(l.id)}">${esc(l.path)}<small>symlink resolves once ${esc((containingMount(l.target,M)||{target:'/'}).target)} is up</small></div>`).join('')}</div></div>
    ${svc.length?`<div class="eyebrow" style="margin:14px 0 6px">Service drop-ins that enforce the order</div><pre class="code panel">${hl(svc.join('\n\n'))}</pre>`:''}</div></section>`;
}

/* topology */
function vTopology(){
  const M=collectMounts();
  const tn=(node,b,s,cls,extra='')=>`<div class="tn ${cls||''}" data-node="${esc(node)}" ${extra}><b>${b}</b>${s?`<span>${s}</span>`:''}</div>`;
  const col0=[],col1=[],col2=[],col3=[],col4=[];
  ['fast','mass','remote'].forEach(t=>{
    const ds=S.disks.filter(d=>d.tier===t);const rs=t==='remote'?S.remotes:[];
    if(!ds.length&&!rs.length) return;
    col0.push(`<div class="tgrp ${t}">${t==='fast'?'Fast local':t==='mass'?'Mass local':'Remote / mesh'}</div>`);
    ds.forEach(d=>col0.push(tn('disk:'+d.dev,'/dev/'+esc(d.dev),`${esc(d.model.split(' (')[0])} · ${fmtDec(d.size,1)}`,t)));
    rs.forEach(r=>col0.push(tn('rem:'+r.id,`<span class="dot ${r.status==='connected'?'ok':'crit'}"></span>${esc(r.name)}`,`${esc(r.proto)} via ${esc(r.via)}`,'remote'+(r.status==='connected'?'':' bad'))));
  });
  ['fast','mass','remote'].forEach(t=>{
    const parts=allParts().filter(x=>x.d.tier===t&&!x.p.member);const pools=S.pools.filter(p=>p.tier===t);
    if(!parts.length&&!pools.length) return;
    col1.push(`<div class="tgrp ${t}">${t} tier</div>`);
    parts.forEach(({p})=>col1.push(tn('part:'+p.id,esc(p.id),`${esc(p.fs)} · ${fmtBin(p.size,1)}`,t)));
    pools.forEach(p=>{const r=calcEngine(poolCalc(p));col1.push(tn('pool:'+p.name,esc(p.name),`${p.type} ${esc(p.level)} · ${fmtBin(r.usable,1)} usable`,t))});
  });
  allParts().forEach(({p,d})=>{ if(p.fs==='btrfs'&&p.subvols) p.subvols.forEach(sv=>col2.push(tn(`sv:${p.id}/${sv.name}`,esc(sv.name),`btrfs subvol · ${esc(p.label)}`,d.tier))) });
  S.pools.forEach(p=>(p.datasets||[]).forEach(ds=>col2.push(tn(`ds:${p.name}/${ds.name}`,`${esc(p.name)}/${esc(ds.name)}`,`rs=${esc(ds.recordsize)} · ${esc(ds.compression)}`,p.tier))));
  const seen=new Set();
  M.filter(m=>m.kind!=='bind'&&m.kind!=='swap').sort((a,b)=>a.target.localeCompare(b.target)).forEach(m=>{ if(seen.has(m.target)) return; seen.add(m.target); col3.push(tn('mnt:'+m.target,esc(m.target),`${esc(m.fs)}${m.opts.length?' · '+esc(m.opts.filter(o=>!o.startsWith('subvol')).slice(0,2).join(',')):''}`,m.tier)) });
  S.links.forEach(l=>{const h=linkHealth(l,M);col4.push(tn('link:'+l.id,esc(l.path),`${esc(l.kind)} → ${esc(l.target)}`,h.state!=='ok'?'bad':'',`style="--tc:var(--${h.state==='ok'?'ok':h.state})"`))});
  col4.push('<div class="tgrp remote" style="--tc:var(--muted)">Exports</div>');
  S.exports.forEach(e=>col4.push(tn('exp:'+e.id,`${esc(e.proto)} · ${esc(e.name)}`,`${esc(e.path)} · ${esc(e.clients)}`,'',`style="--tc:var(--accent)"`)));
  const col=(h,a)=>`<div class="tcol"><div class="eyebrow">${h}</div>${a.join('')}</div>`;
  return `<div class="legend"><span><i style="--fc:var(--fast)"></i>fast tier</span><span><i style="--fc:var(--mass)"></i>mass tier</span><span><i style="--fc:var(--remote)"></i>remote / mesh</span><span>dashed edge = SLOG / L2ARC</span><span>red border = broken or offline</span></div>
  <section class="panel"><div class="pb topo-wrap"><div class="topo" id="topo"><svg id="edges" aria-hidden="true"></svg>
    ${col('Physical &amp; network devices',col0)}${col('Partitions · pools · arrays',col1)}${col('Subvolumes &amp; datasets',col2)}${col('Mount points',col3)}${col('Links &amp; exports',col4)}</div></div></section>
  <section class="panel"><div class="ph"><h2>ASCII topology</h2><button type="button" class="btn sm" data-act="copy" data-src="ascii">Copy</button></div><pre class="code" id="ascii">${esc(genASCII())}</pre></section>`;
}
function drawEdges(){
  const topo=$('#topo');const svg=$('#edges');if(!topo||!svg) return;
  const base=topo.getBoundingClientRect();
  const el=id=>topo.querySelector(`.tn[data-node="${CSS.escape(id)}"]`);
  const rep=id=>{ if(el(id)) return id; if(id.startsWith('part:')){const x=findPart(id.slice(5));if(x) return 'disk:'+x.d.dev} return null };
  const colOf=e=>[...topo.children].indexOf(e.closest('.tcol'));
  const out=[];const done=new Set();
  buildGraph().forEach(([a,b,k])=>{
    const ra=rep(a),rb=rep(b);if(!ra||!rb||ra===rb) return;const key=ra+'|'+rb;if(done.has(key)) return;done.add(key);
    const ea=el(ra),eb=el(rb);if(colOf(ea)>=colOf(eb)) return;
    const A=ea.getBoundingClientRect(),B=eb.getBoundingClientRect();
    const x1=A.right-base.left,y1=A.top+A.height/2-base.top,x2=B.left-base.left,y2=B.top+B.height/2-base.top;const dx=Math.max(24,(x2-x1)/2);
    out.push(`<path class="edge ${k}" data-a="${esc(ra)}" data-b="${esc(rb)}" d="M${x1},${y1} C${x1+dx},${y1} ${x2-dx},${y2} ${x2},${y2}"/>`);
  });
  svg.setAttribute('width',topo.scrollWidth);svg.setAttribute('height',topo.scrollHeight);
  svg.innerHTML=out.join('');
}

/* RAID */
function defaultCalc(){ const p=poolBy('tank'); const c=p?poolCalc(p):{layout:'zfs-raidz2',sizes:Array(6).fill(20e12),width:6,recordsize:1048576,ashift:12,fill:.7,speed:180,ure:1e-15,fs:'ext4',reserve:true,virt:0}; c.recordsize=1048576; return c }
function vRaid(){
  const c=UI.calc||(UI.calc=defaultCalc());const r=calcEngine(c);const [fam]=c.layout.split('-');
  const raw=r.raw||1;const seg=(v,cls,t)=>v>0?`<i class="${cls}" style="width:${(v/raw*100).toFixed(3)}%" title="${t}: ${fmtDec(v)}"></i>`:'';
  const LAYOUTS=[['OpenZFS',['zfs-stripe','zfs-mirror','zfs-raidz1','zfs-raidz2','zfs-raidz3']],['mdadm',['md-raid0','md-raid1','md-raid5','md-raid6','md-raid10']],['Btrfs profiles',['btrfs-single','btrfs-raid1','btrfs-raid1c3','btrfs-raid10']],['LVM',['lvm-linear','lvm-thin']]];
  const sizesTB=c.sizes.map(x=>+(x/1e12).toFixed(2));
  const fsSel=fam==='md'||fam==='lvm';
  return `<div class="calc">
  <section class="panel"><div class="ph"><h2>Inputs</h2><div class="row"><button type="button" class="btn sm" data-act="cload" data-id="tank">Load tank</button><button type="button" class="btn sm" data-act="cload" data-id="md0">Load md0</button><button type="button" class="btn sm" data-act="cload" data-id="mixed">Mixed sizes</button></div></div><div class="pb stack">
    <label class="f">Layout<select id="c-layout" data-c="layout">${LAYOUTS.map(([g,ls])=>`<optgroup label="${g}">${ls.map(l=>`<option value="${l}" ${l===c.layout?'selected':''}>${l.replace('-',' · ')}</option>`).join('')}</optgroup>`).join('')}</select></label>
    <div><div class="eyebrow" style="margin-bottom:6px">Drives (decimal TB, as labelled)</div><div class="drv">${sizesTB.map((t,i)=>`<span class="d"><input type="number" step="0.01" min="0.1" id="c-d-${i}" value="${t}" data-c="drive" data-i="${i}" aria-label="Drive ${i+1} size in TB">TB<button type="button" class="xbtn" data-act="cdel" data-i="${i}" aria-label="Remove drive ${i+1}">×</button></span>`).join('')}</div>
      <div class="row" style="margin-top:8px"><input type="number" id="c-addn" value="1" min="1" max="24" style="width:60px" aria-label="Number of drives to add">×<input type="number" id="c-addtb" value="${sizesTB[sizesTB.length-1]||20}" step="0.01" style="width:80px" aria-label="Size in TB">TB<button type="button" class="btn sm" data-act="cadd">Add drives</button></div></div>
    <div class="fields">
      ${fam==='zfs'&&!c.layout.endsWith('stripe')?`<label class="f">${c.layout.endsWith('mirror')?'Mirror width':'vdev width'}<input type="number" id="c-width" min="2" max="${c.sizes.length}" value="${c.width}" data-c="width"></label>`:''}
      ${fam==='zfs'?`<label class="f">recordsize<select id="c-rs" data-c="recordsize">${[16384,65536,131072,1048576].map(v=>`<option value="${v}" ${v===c.recordsize?'selected':''}>${fmtBin(v,0).replace(' ','')}</option>`).join('')}</select></label>
        <label class="f">ashift<select id="c-ashift" data-c="ashift">${[9,12,13].map(v=>`<option value="${v}" ${v==c.ashift?'selected':''}>${v} · ${2**v} B</option>`).join('')}</select></label>`:''}
      ${fsSel?`<label class="f">Filesystem<select id="c-fs" data-c="fs">${['ext4','xfs','btrfs'].map(v=>`<option ${v===c.fs?'selected':''}>${v}</option>`).join('')}</select></label>
        ${c.fs==='ext4'?`<label class="f">ext4 root reserve<select id="c-res" data-c="reserve"><option value="1" ${c.reserve?'selected':''}>5% (default)</option><option value="0" ${!c.reserve?'selected':''}>0% (-m 0)</option></select></label>`:''}`:''}
      ${c.layout==='lvm-thin'?`<label class="f">Virtual volumes (TB)<input type="number" id="c-virt" step="0.1" value="${(c.virt/1e12).toFixed(1)}" data-c="virt"></label>`:''}
      <label class="f">Pool fill for rebuild<input type="number" id="c-fill" min="5" max="100" value="${Math.round(c.fill*100)}" data-c="fill"></label>
      <label class="f">Rebuild speed (MB/s)<input type="number" id="c-speed" min="10" max="5000" value="${c.speed}" data-c="speed"></label>
      <label class="f full">Drive URE class<select id="c-ure" data-c="ure"><option value="1e-14" ${c.ure===1e-14?'selected':''}>Consumer · 1 per 10¹⁴ bits</option><option value="1e-15" ${c.ure===1e-15?'selected':''}>Enterprise / NAS · 1 per 10¹⁵ bits</option><option value="1e-16" ${c.ure===1e-16?'selected':''}>Enterprise SAS / SSD · 1 per 10¹⁶ bits</option></select></label>
    </div></div></section>
  <section class="stack">
    <div class="panel pb stack">
      <span class="eyebrow">Usable capacity</span>
      <div class="big">${fmtDec(r.usable,2)}<small>${fmtBin(r.usable,2)}</small></div>
      <span class="muted">${(r.usable/raw*100).toFixed(1)}% of ${fmtDec(r.raw)} raw (${fmtBin(r.raw)}) across ${c.sizes.length} drives</span>
      <div class="capbar">${seg(r.usable,'c-use','Usable')}${seg(r.parity,'c-par','Parity / mirror copies')}${seg(r.overhead,'c-ovh','Padding, slop, metadata')}${seg(r.waste,'c-waste','Mixed-size waste')}${seg(r.unused,'c-unused','Unused drives')}</div>
      <div class="legend"><span><i style="--fc:var(--accent)"></i>usable ${fmtBin(r.usable)}</span><span><i style="--fc:var(--mass)"></i>parity / copies ${fmtBin(r.parity)}</span><span><i style="--fc:var(--remote)"></i>padding, slop &amp; fs metadata ${fmtBin(r.overhead)}</span>${r.waste?`<span><i style="--fc:var(--crit)"></i>mixed-size waste ${fmtBin(r.waste)}</span>`:''}${r.unused?`<span><i style="--fc:var(--faint)"></i>unused ${fmtBin(r.unused)}</span>`:''}</div>
    </div>
    <div class="metrics">
      <div class="metric"><span class="eyebrow">Fault tolerance</span><span class="v" style="color:var(--${r.tol>=2?'ok':r.tol===1?'warn':'crit'})">${r.tol} drive${r.tol===1?'':'s'}</span><span class="s">${esc(r.tolNote)}</span></div>
      <div class="metric"><span class="eyebrow">Rebuild window</span><span class="v">${r.tol?r.rebuildH.toFixed(1)+' h':'—'}</span><span class="s">${r.tol?`largest drive at ${c.speed} MB/s${fam==='zfs'||fam==='btrfs'?`, ${Math.round(c.fill*100)}% allocated`:', full-surface resync'}`:'nothing to rebuild from'}</span></div>
      <div class="metric"><span class="eyebrow">URE exposure</span><span class="v" style="color:var(--${r.ureLevel==='High'?'crit':r.ureLevel==='Moderate'?'warn':'ok'})">${r.ureLevel}</span><span class="s">${r.tol?`${(r.ureP*100).toFixed(1)}% chance of ≥1 URE while rebuilding${r.tol>=2?'; corrected from remaining parity':''}`:'no redundancy'}</span></div>
      <div class="metric"><span class="eyebrow">Write amplification</span><span class="v">${r.waSeq.toFixed(2)}× <small class="muted" style="font-size:12px">seq</small> · ${r.waSmall}× <small class="muted" style="font-size:12px">${fam==='md'&&/raid[56]/.test(c.layout)?'I/Os':'small'}</small></span><span class="s">${esc(r.waNote)}</span></div>
    </div>
    ${r.notes.length?`<div class="stack">${r.notes.map(n=>`<div class="note ${n[0]==='info'?'':n[0]}">${esc(n[1])}</div>`).join('')}</div>`:''}
    <div class="note">Drive labels use decimal TB (10¹²). Operating systems and ZFS report binary TiB (2⁴⁰), so a “20 TB” drive shows as ${fmtBin(20e12)}. ZFS also holds back slop space (1/32 of the pool, capped at 128 GiB) and loses some space to RAIDZ parity padding at small recordsizes.</div>
  </section></div>`;
}

/* protection */
function vProtection(){
  const rows=S.protection.map((r,i)=>{const st=protStatus(r);const c=copies321(r);const age=r.backup.target?daysSince(r.backup.last):null;
    const sk=r.sync.state==='Active Sync'?'ok':r.sync.state==='Rsync Scheduled'?'ok':r.sync.state==='None'?'muted':r.sync.state==='Lagging'?'warn':'crit';
    const path=(collectMounts().find(m=>m.node===r.node)||{}).target||'';
    return `<tr data-node="${esc(r.node)}">
      <td><b class="mono">${esc(r.name)}</b><div class="muted mono" style="font-size:11.5px">${esc(path)}</div>${r.deployed?`<div class="muted" style="font-size:11px">From: ${esc(r.deployed.join(', '))}</div>`:''}</td>
      <td><div class="pcell" data-act="psync" data-i="${i}" role="button" tabindex="0" title="Click to cycle sync state"><span class="st ${sk}">${esc(r.sync.state)}</span><small>${esc(r.sync.target||'no replication')}${r.sync.lag?' · lag '+esc(r.sync.lag):''}</small></div></td>
      <td><div class="pcell" data-act="psnap" data-i="${i}" role="button" tabindex="0" title="Click to toggle snapshots"><span class="st ${r.snap.on?'ok':'crit'}">${r.snap.on?esc(r.snap.tool):'No snapshots'}</span><small>${r.snap.on?`${esc(r.snap.policy)} · ${r.snap.count} kept · ${fmtBin(r.snap.overhead,1)}`:'click to enable'}</small></div></td>
      <td><span class="st ${r.backup.target?(r.backup.offsite?'ok':'warn'):'crit'}">${esc(r.backup.target||'No backup')}</span><div class="muted mono" style="font-size:11px">${r.backup.target?`${r.backup.offsite?'offsite':'same site'} · ${r.backup.ratio.toFixed(2)}× compression`:''}</div></td>
      <td class="mono" style="font-size:11.5px">${esc(r.backup.enc)}</td>
      <td>${r.backup.target?`<span class="st ${age>90?'crit':age>30?'warn':'ok'} num">${r.backup.last?esc(r.backup.last):'No good run yet'}</span>${r.backup.last?`<div class="muted" style="font-size:11px">${age} days ago</div>`:''}${r.deployed?'':`<button type="button" class="btn sm ghost" style="margin-top:4px" data-act="pval" data-i="${i}">Mark validated</button>`}`:'<span class="muted">—</span>'}</td>
      <td class="num mono" style="font-size:12px">${c.c} cop${c.c>1?'ies':'y'}<br><span class="muted">${c.off?'offsite ✓':c.unstated?'offsite not stated':'no offsite'}</span></td>
      <td><span class="pill ${st.k}">${st.t}</span><div class="why">${esc(st.why.join(' · '))}</div></td></tr>`}).join('');
  const P=S.protection.map(protStatus);
  return `<div class="grid g4">${[['ok','Protected','Snapshots plus a validated offsite copy'],['warn','Local only','A copy is missing, stale or on the same site'],['crit','Critical','Stale sync, unvalidated backup or a single copy'],['muted','Excluded','Ephemeral scratch, not tracked']].map(([k,t,d])=>`<div class="panel kpi"><span class="pill ${k}">${t}</span><span class="v">${P.filter(x=>x.k===k).length}</span><span class="s">${d}</span></div>`).join('')}</div>
  <section class="panel"><div class="ph"><h2>3-2-1 health grid</h2><span class="sub">Click a sync or snapshot cell to simulate a state change</span>${DOC.host&&DOC.signedIn?`<button type="button" class="btn sm ghost" data-act="offsite" title="Backups that run on this host count as offsite">${DOC.offsite?'This host is offsite':'Mark this host offsite'}</button>`:''}</div>
  <div class="tw"><table style="min-width:1080px"><thead><tr><th>Dataset</th><th>Synced</th><th>Snapshots</th><th>Backup</th><th>Encryption</th><th>Last validated</th><th>3-2-1</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
}

/* export */
const EXPORTS=[['changes','Change plan'],['units','systemd units'],['fstab','/etc/fstab'],['json','Blueprint JSON'],['yaml','Blueprint YAML'],['ascii','ASCII tree']];
const CH_DRAFT='sf.changes.draft';                     // the Changes tab's staged plan (static/changes.js)
/* The server compares the design with the latest scan and answers with change-plan tasks: drive and mount changes
   are checked, reported first and deployed from Changes like any other, instead of a script written here. */
async function loadDesignChanges(){
  const body=JSON.stringify(blueprint()),key=DOC.host+'\n'+body;
  if(UI.diff&&UI.diff.key===key) return;
  UI.diff={key,loading:true};
  try{ const r=await apiJSON('/api/planner/changes',{method:'POST',headers:{'Content-Type':'application/json'},body});
    if(UI.diff.key===key) UI.diff={key,r} }
  catch(e){ if(UI.diff.key===key) UI.diff={key,error:e.message} }
  if(UI.view==='export'&&UI.exportTab==='changes') render();
}
function vDesignChanges(){
  if(!DOC.signedIn||!DOC.host) return `<div class="pb muted">Sign in and open a scanned host to turn this design into a change plan. The example host is never scanned, so it has no plan.</div>`;
  if(!DOC.scanned) return `<div class="pb muted">${esc(DOC.host)} has not been scanned. Change plans are checked against a scan: scan it, then come back. The fstab, systemd and blueprint exports work without one.</div>`;
  loadDesignChanges();                                 // no-op while the design is unchanged
  const d=UI.diff;
  if(d.loading){ return `<div class="pb muted">Comparing the design with the last scan of ${esc(DOC.host)}…</div>` }
  if(d.error) return `<div class="pb"><div class="note crit">${esc(d.error)}</div></div>`;
  const r=d.r,pl=(n,w)=>`${n} ${w}${n===1?'':'s'}`;
  const tasks=r.tasks.map((t,i)=>`<div class="titem"><span class="n">${i+1}. ${esc(taskLabel(t))}</span><span class="r">${t.type==='partition'||t.type==='format'||t.type==='btrfs-add'?'Destroys data on the device: in Changes, open it with Edit and type the device again before it can be saved.':''}</span><span class="z"><span class="pill ${['partition','format','btrfs-add'].includes(t.type)?'crit':'info'}">${esc(t.type)}</span></span></div>`).join('');
  const manual=r.manual.map(m=>`<li><b>${esc(m.what)}</b>: ${esc(m.why)}</li>`).join('');
  const left=r.left.map(x=>`<li>${esc(x)}</li>`).join('');
  return `<div class="pb stack">
    ${r.tasks.length?`<div class="row" style="justify-content:space-between"><span>${pl(r.tasks.length,'task')} to bring ${esc(r.host)} to this design${r.destructive?`, ${r.destructive} of them on drives`:''}.</span><button type="button" class="btn sm pri" data-act="stagechanges">Stage in Changes</button></div><div>${tasks}</div>`
      :`<div class="note ok">${esc(r.host)} already matches this design as far as change plans go.</div>`}
    ${manual?`<div><h3 style="font-size:13px;margin:6px 0">By hand</h3><p class="muted" style="font-size:12px;margin:0 0 6px">Change plans have no task for these. Do them yourself, rescan, then come back for the rest.</p><ul style="font-size:12px;margin:0;padding-left:18px">${manual}</ul></div>`:''}
    ${left?`<div><h3 style="font-size:13px;margin:6px 0">Left alone</h3><p class="muted" style="font-size:12px;margin:0 0 6px">On the host but not in the design. The plan never removes anything: stage an Unmount yourself if you mean it.</p><ul style="font-size:12px;margin:0;padding-left:18px">${left}</ul></div>`:''}
  </div>`;
}
function taskLabel(t){ const p=t.params;
  return ({partition:()=>`Partition ${p.disk}${p.fstype?' and format it '+p.fstype:''}`,format:()=>`Format ${p.device} as ${p.fstype}`,
    'btrfs-add':()=>`Add ${p.device} to the btrfs pool at ${p.target}`,label:()=>`Label ${p.target} "${p.label}"`,
    'btrfs-balance':()=>`Convert ${p.target} to ${p.data}/${p.metadata}`,subvolume:()=>`Create subvolume ${p.path}`,
    mount:()=>`Mount ${p.source}${p.subvol?'['+p.subvol+']':''} at ${p.target}`,'mount-options':()=>`Mount options of ${p.target}: ${p.options}`,
    symlink:()=>`Link ${p.path} → ${p.target}`}[t.type]||(()=>t.type))() }
function stageDesignChanges(){
  const r=UI.diff&&UI.diff.r;if(!r||!r.tasks.length) return;
  let draft;try{ draft=JSON.parse(localStorage.getItem(CH_DRAFT)||'null') }catch(e){ draft=null }
  if(!draft||!Array.isArray(draft.tasks)) draft={name:'',tasks:[]};
  const same=(a,b)=>a.type===b.type&&a.host===b.host&&JSON.stringify(a.params)===JSON.stringify(b.params);
  const stamp=Date.now().toString(36);
  const add=r.tasks.filter(t=>!draft.tasks.some(x=>same(x,t))).map((t,i)=>({...t,id:'d'+stamp+i}));
  draft.tasks.push(...add);
  if(!draft.name) draft.name=r.name;
  try{ localStorage.setItem(CH_DRAFT,JSON.stringify(draft)) }catch(e){ docState('Your browser blocks storage, so the plan cannot be handed to Changes','err');return }
  location.href=appLink('changes');
}
function vExport(){
  const t=UI.exportTab;
  const tabs=`<div class="tabs" role="tablist">${EXPORTS.map(([k,l])=>`<button type="button" role="tab" class="${k===t?'on':''}" data-act="etab" data-t="${k}">${l}</button>`).join('')}</div>`;
  if(t==='changes') return `<section class="panel"><div class="ph">${tabs}</div>${vDesignChanges()}</section>`;
  const code={units:genUnits,fstab:genFstab,json:()=>JSON.stringify(blueprint(),null,2),yaml:()=>'# StorageForge blueprint'+toYAML(blueprint()),ascii:genASCII}[t]();
  return `<div class="note">These describe the design. To make a host match it, use the Change plan tab: its tasks are checked against the index and reported before they apply.</div>
  <section class="panel"><div class="ph">${tabs}
  <div class="row"><span class="muted" style="font-size:12px">${code.split('\n').length} lines</span><button type="button" class="btn sm pri" data-act="copy" data-src="ecode">Copy</button></div></div>
  <pre class="code" id="ecode" style="max-height:none">${t==='json'?esc(code):hl(code)}</pre></section>`;
}

/* ───────────── blueprint → planner model ───────────── */
function fromBlueprint(bp){
  bp=scrub(bp);
  const md=bp.metadata||{};const bare=x=>String(x||'').replace(/^\/dev\//,'');
  const s={host:md.host||'host',idMode:md.identifiers==='LABEL'?'LABEL':'UUID',
    disks:(bp.devices||[]).map(d=>({dev:bare(d.dev),model:d.model||'unknown model',serial:d.serial||'—',bus:d.bus||'unknown bus',media:d.media||'hdd',
      size:d.sizeBytes||0,lbs:(d.sector||{}).logical||512,pbs:(d.sector||{}).physical||4096,table:d.table||'gpt',tier:d.tier||'mass',member:d.member||undefined,
      parts:(d.partitions||[]).map((p,i)=>({id:p.id,num:p.num||i+1,uuid:p.uuid||undefined,start:p.startBytes!=null?p.startBytes:Math.round((p.startMiB||0)*MiB),size:p.sizeBytes||0,
        fs:p.fs||'none',label:p.label||'',mount:p.mount||undefined,opts:p.options||[],member:p.member||undefined,role:p.role||undefined,
        subvols:p.subvolumes&&p.subvolumes.length?p.subvolumes.map(v=>({name:v.name,mount:v.mount||undefined})):undefined}))})),
    pools:(bp.pools||[]).map(p=>({name:p.name,type:p.type||'mdadm',level:p.level||'stripe',ashift:p.ashift||12,tier:p.tier||'mass',encryption:p.encryption||undefined,
      mount:p.mount||undefined,fs:p.fs||undefined,label:p.label||undefined,opts:p.options||undefined,vg:p.vg||undefined,lv:p.lv||undefined,levelSource:p.levelSource||undefined,datasets:(p.datasets||[]).map(ds=>({...ds}))})),
    remotes:(bp.remotes||[]).map((r,i)=>({id:r.id||'r'+i,name:r.name||r.endpoint,proto:r.protocol||'NFSv4.2',endpoint:r.endpoint||'',via:r.via||'network',
      mount:r.mount||undefined,status:r.status||'connected',capacity:r.capacity??null,opts:r.options||['_netdev','nofail'],raw:r})),
    links:(bp.links||[]).map((l,i)=>({id:'L'+i,kind:l.kind,path:l.path,target:l.target,fromScan:l.fromScan||undefined})),
    // raw: the export as stored, so fields the planner doesn't edit (fromScan, client mounts, ...) survive a save
    exports:(bp.exports||[]).map((e,i)=>({id:'e'+i,proto:e.protocol||e.proto,name:e.name,path:e.path,clients:e.clients||'',opts:e.options||e.opts||'',raw:e})),
    existing:(bp.planner||{}).existing||{},known:(bp.planner||{}).known||[],
    protection:(bp.protection||[]).map(r=>{const sn=r.snapshots||r.snap||{};const b=r.backup||{};
      return {node:r.node||nodeForPath(bp,r.path),name:r.dataset||r.name||r.path||'?',ephemeral:!!r.ephemeral,sync:{state:'None',...(r.sync||{})},
        snap:{on:!!(sn.enabled??sn.on),tool:sn.tool||'none',policy:sn.policy||'',count:sn.count||0,overhead:sn.overhead||0},
        backup:{target:b.target||null,enc:b.enc||'none',ratio:b.ratio||1,last:b.last||null,offsite:!!b.offsite},...(r.deployed?{deployed:r.deployed,hand:r.hand}:{})}})};
  // whole-disk members are recorded per pool in the blueprint; the planner keeps them on the disk
  (bp.pools||[]).forEach(p=>(p.members||[]).map(bare).forEach(m=>{const d=s.disks.find(x=>x.dev===m);if(d&&!d.parts.some(x=>x.id===m)) d.member=p.name}));
  return tidy(s);
}
function nodeForPath(bp,path){ const S0=S;try{ S=fromBlueprint({...bp,protection:[]});const m=collectMounts().find(x=>x.target===path);return m?m.node:'path:'+path }finally{ S=S0 } }

/* ───────────── server: hosts, load, save ───────────── */
async function apiJSON(path,opts={}){
  // the kernel's api() ends the page on a 401, and on a 403 that wants the password it asks right here and retries: this used to say "run the change from the main page"
  const r=await api(path,opts);
  return r.json().catch(()=>({}));
}
/* the main page on one of its panels for this host: /#host=…&tab=… */
const APP_TABS=[['changes','Changes'],['moves','Moves'],['deploy','Deploy'],['docker','Docker'],['git','Git'],['copies','Cleanup'],['access','Access']];
const appLink=tab=>{const q=new URLSearchParams();if(DOC.host)q.set('host',DOC.host);if(tab)q.set('tab',tab);const h=q.toString();return '/'+(h?'#'+h:'')};
function appLinks(){
  $('#tograph').href=appLink('');
  const box=$('#applinks');box.querySelector('.rail-btns')?.remove();
  if(!DOC.host||!DOC.signedIn) return;
  const row=document.createElement('div');row.className='rail-btns';
  row.append(...APP_TABS.map(([t,l])=>Object.assign(document.createElement('a'),{className:'btn sm ghost',href:appLink(t),textContent:l})));
  box.append(row);
}
async function loadActivity(){
  const h=DOC.host;DOC.activity=null;if(!h||!DOC.signedIn) return;
  try{ const a=await apiJSON('/api/planner/activity?host='+encodeURIComponent(h)); if(DOC.host===h){DOC.activity=scrub(a);if(UI.view==='overview') render()} }
  catch(e){ if(DOC.host===h){DOC.activity={host:h,changes:[],moves:[],shares:null,jobs:[],deployed:[],drift:[],unreadable:null};if(UI.view==='overview') render()} }
}
async function setExample(show){
  $('#dropconfirm').hidden=true;
  try{
    await apiJSON('/api/planner/example',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({show})});
    if(!show) dropDraft('');
    await loadHosts();
    if(show) openDoc('');
    else if(!DOC.host&&!exampleShown()) openDoc(DOC.hosts[0].host);
  }catch(e){ docState(e.message,'err') }
}
function docState(msg,cls){
  const el=$('#docstate');el.className=cls||(DOC.dirty?'dirty':'muted');
  el.textContent=msg||(!DOC.host?'Example design. Edits stay in this browser.'
    :DOC.dirty?'Unsaved changes (kept in this browser).'
    :DOC.source==='scan'?'Built from the latest scan. Save it to keep your design.'
    :'Saved design · '+fmtTime(DOC.savedAt));
  $('#savedesign').hidden=!DOC.host||!DOC.signedIn;$('#versions').hidden=!DOC.host||!DOC.signedIn;$('#fromscan').hidden=!DOC.host||!DOC.scanned||!DOC.signedIn;
  $('#reset').hidden=!!DOC.host;$('#hostpick').value=DOC.host;
  $('#dropexample').hidden=!!DOC.host||!DOC.signedIn||!DOC.example||!DOC.hosts.length||!$('#dropconfirm').hidden;
  $('#showexample').hidden=!DOC.signedIn||DOC.example;
  appLinks();
}
async function loadHosts(){
  try{
    const {hosts,example}=await apiJSON('/api/planner/hosts');DOC.signedIn=true;DOC.hosts=scrub(hosts);DOC.example=example!==false;$('#signin').hidden=true;
    const sel=$('#hostpick');
    sel.replaceChildren(...(exampleShown()?[new Option('Example host “atlas”','')]:[]),...hosts.map(h=>new Option(`${h.host}${h.saved?' · saved':''}${h.scanned?' · scanned':''}`,h.host)));
    sel.value=DOC.host;docState();
  }catch(e){ /* signed out: the example still works */ }
}
async function openDoc(host,source,push){
  if(DOC.host&&DOC.dirty&&!(await confirmDialog({ title: `Leave ${DOC.host} with unsaved changes?`, body: 'They stay as a draft in this browser.', confirm: 'Leave', danger: true }))){ $('#hostpick').value=DOC.host;return }
  if(!host){ DOC.host='';DOC.source='example';DOC.dirty=false;DOC.activity=null;S=load('')||sample();UI.sel=null;UI.calc=null;render();docState();setHash(push);return }
  docState('Loading '+host+'…');
  try{
    const r=await apiJSON('/api/planner/design?host='+encodeURIComponent(host)+(source?'&source='+source:''));
    DOC.offsite=!!r.offsite;
    const draft=!source&&load(host);
    Object.assign(DOC,{host,source:r.source,savedAt:r.saved_at,scanned:r.scanned,dirty:!!draft});
    S=draft||fromBlueprint(r.blueprint);if(!source) normalizeIds();UI.sel=null;UI.calc=null;render();docState();setHash(push);loadActivity();
  }catch(e){ docState(e.message,'err') }
}
function normalizeIds(){ S.links.forEach((l,i)=>{l.id=l.id||'L'+i}); }
async function saveDesign(){
  docState('Saving…');
  try{
    const r=await apiJSON('/api/planner/design',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(blueprint())});
    dropDraft(DOC.host);Object.assign(DOC,{source:'saved',savedAt:r.saved_at,dirty:false});
    docState(`Saved · graph ${r.graph?r.graph.nodes+' nodes':'unchanged'}`,'muted');setTimeout(()=>docState(),4000);loadHosts();render();
  }catch(e){ docState(e.message,'err') }
}
/* ───────────── versions: named copies of the design, to compare, restore or delete (UX-38, 3g) ─────────────
   The panel is the kernel's modal, built with DOM calls only: every name, note, author and sentence the server sends goes in as text. A
   version is kept from, and compared with, the design on screen (saved or not). Restoring writes the version as the host's saved design;
   the server keeps the design it replaces as an automatic version first, and the page then reloads the host's design from the server. */
const jsonOpts=(method,body)=>({method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
const CHANGE_GROUPS=[['only_version','Only in this version','Restoring brings these back.'],
  ['only_current','Only in the current design','Restoring takes these away.'],
  ['different','Different','Restoring sets these as the version had them.']];
async function openVersions(){
  const host=DOC.host;if(!host||!DOC.signedIn) return;
  const title=sfNode('h2',{id:'pv-title'},'Versions of ',sfNode('code',{},host));
  const intro=sfNode('p',{class:'muted'},'A version is a copy of the whole design as it is on screen now, saved or not. Restoring one replaces the saved design and first keeps the current one as an automatic version, so nothing is lost.');
  const name=sfNode('input',{type:'text',id:'pv-name',maxlength:80,autocomplete:'off',spellcheck:false,placeholder:'Version name (optional)','aria-label':'Version name'});
  const note=sfNode('input',{type:'text',id:'pv-note',maxlength:500,autocomplete:'off',spellcheck:false,placeholder:'Note (optional)','aria-label':'Note'});
  const keep=sfNode('button',{type:'button',class:'sf-btn pri',id:'pv-save'},'Save this design as a version');
  const err=sfNode('p',{class:'sf-err',role:'alert',id:'pv-err',hidden:true});
  const count=sfNode('p',{class:'muted small',id:'pv-count'});
  const list=sfNode('ul',{class:'pv-list',id:'pv-list'});
  const result=sfNode('div',{class:'pv-result',id:'pv-result',tabindex:-1});
  const close=sfNode('button',{type:'button',class:'sf-btn ghost',id:'pv-close'},'Close');
  const root=sfNode('div',{class:'pv-body'},title,intro,sfNode('div',{class:'pv-save'},name,note,keep),err,count,list,result,sfNode('div',{class:'sf-actions'},close));
  const dlg=sfModal(root,'pv-title');dlg.classList.add('pv');
  close.addEventListener('click',()=>dlg.close());
  const say=msg=>{err.textContent=msg||'';err.hidden=!msg};
  const attempt=async work=>{ say(''); try{ return await work() }catch(e){ say(e.message); return null } };

  function showCompare(c){
    const kids=[sfNode('h3',{},`“${c.version.name}” against the current design`),sfNode('p',{class:c.same?'':'muted'},c.summary)];
    for(const [key,head,hint] of CHANGE_GROUPS){
      const rows=c.changes.filter(x=>x.change===key);if(!rows.length) continue;
      kids.push(sfNode('h4',{},`${head} (${rows.length})`),sfNode('p',{class:'muted small'},hint),sfNode('ul',{},rows.map(r=>sfNode('li',{},r.text))));
    }
    if(c.truncated) kids.push(sfNode('p',{class:'muted small'},`${c.truncated} more are not listed.`));
    result.replaceChildren(...kids);result.focus();
  }
  async function compare(v,button){
    const c=await attempt(()=>withBusy(button,async()=>apiJSON('/api/planner/versions/compare',jsonOpts('POST',{id:v.id,blueprint:blueprint()}))));
    if(c) showCompare(c);return c;
  }
  async function restore(v,button){
    const c=await attempt(()=>apiJSON('/api/planner/versions/compare',jsonOpts('POST',{id:v.id,blueprint:blueprint()})));
    if(!c) return;
    const ok=await confirmDialog({title:`Restore “${v.name}”?`,confirm:'Restore',
      body:`${c.summary}\n\nThe design on screen is replaced by this version and saved as the design for ${host}. The design it replaces is kept first as an automatic version, so you can come back to it.`,
      items:c.changes.slice(0,8).map(x=>x.text)});
    if(!ok) return;
    const r=await attempt(()=>withBusy(button,()=>apiJSON('/api/planner/versions/restore',jsonOpts('POST',{id:v.id,current:blueprint()}))));
    if(!r) return;
    dropDraft(host);DOC.dirty=false;dlg.close();
    await openDoc(host);loadHosts();
    notify(r.kept?`Restored “${v.name}”. The design it replaced is kept as “${r.kept.name}”.`:`Restored “${v.name}”.`);
  }
  async function remove(v,button){
    const ok=await confirmDialog({title:`Delete “${v.name}”?`,body:'The version is deleted. The design on screen and the saved design are not changed.',confirm:'Delete',danger:true});
    if(!ok) return;
    if(await attempt(()=>withBusy(button,()=>apiJSON('/api/planner/versions/'+v.id,{method:'DELETE'})))){ result.replaceChildren();await refresh() }
  }
  function row(v){
    const btn=(label,cls,fn)=>{const b=sfNode('button',{type:'button',class:'sf-btn '+cls,'data-act':label.toLowerCase(),'aria-label':`${label} ${v.name}`},label);sfOnClick(b,()=>fn(v,b));return b};
    return sfNode('li',{class:'pv-item','data-id':v.id},
      sfNode('div',{class:'pv-head'},sfNode('b',{class:'pv-name'},v.name),v.auto?sfNode('span',{class:'pv-auto'},'kept automatically'):null),
      sfNode('div',{class:'muted small'},`${v.author} · ${fmtTime(v.created_at)} · ${fmtBytes(v.size_bytes)}`),
      v.note?sfNode('div',{class:'pv-note small'},v.note):null,
      sfNode('div',{class:'pv-actions'},btn('Compare','ghost',compare),btn('Restore','',restore),btn('Delete','ghost',remove)));
  }
  async function refresh(){
    const r=await attempt(()=>apiJSON('/api/planner/versions?host='+encodeURIComponent(host)));
    if(!r) return;
    list.replaceChildren(...(r.versions.length?r.versions.map(row):[sfNode('li',{class:'muted',id:'pv-empty'},'No versions yet.')]));
    count.textContent=`${r.versions.length} of at most ${r.max_versions} kept for this host.`;
  }
  sfOnClick(keep,async()=>{
    const v=await attempt(()=>apiJSON('/api/planner/versions',jsonOpts('POST',{host,blueprint:blueprint(),name:name.value,note:note.value})));
    if(!v) return;
    name.value='';note.value='';await refresh();announce(`Saved ${v.name}`);
  });
  await refresh();
  name.focus();
}
/* The planner's place is in its URL too (UX-08): #/devices?host=nas, the way the main page writes its own. The old #devices@nas is still read.
   Choosing a view or a host is a step in the history, so Back goes where the person was; loading a design is not. */
function readHash(){
  const p=sfParseHash();
  if(!p.legacy&&p.parts.length) return {view:p.parts[0],host:p.q.get('host')||''};
  const [view,host]=(location.hash||'').slice(1).split('@');
  return {view:view||'',host:decodeURIComponent(host||'')};
}
function setHash(push){ try{ (push?sfPushHash:sfReplaceHash)(sfFormatHash([UI.view],{host:DOC.host})) }catch(e){} }

/* ───────────── events ───────────── */
function selObj(){
  const s=UI.sel;if(!s) return null;
  if(s.type==='part') return findPart(s.id)?.p;
  if(s.type==='pool') return poolBy(s.id);
  if(s.type==='disk') return diskBy(s.id);
  if(s.type==='rem') return remoteBy(s.id);
}
function commit(){ save(); render(); }
function commitSoon(){ save(); renderSoon(); }
function selectNode(node){
  const [t,...r]=node.split(':');const v=r.join(':');
  if(t==='part') UI.sel={type:'part',id:v};
  else if(t==='sv') UI.sel={type:'part',id:v.split('/')[0]};
  else if(t==='disk') UI.sel={type:'disk',id:v};
  else if(t==='pool') UI.sel={type:'pool',id:v};
  else if(t==='ds') UI.sel={type:'pool',id:v.split('/')[0]};
  else if(t==='rem') UI.sel={type:'rem',id:v};
}
function go(view){ UI.view=view; setHash(true); render(); $('#main').scrollTop=0; }
$('#nav').addEventListener('click',e=>{const b=e.target.closest('[data-view]');if(b) go(b.dataset.view)});
$('#idmode').addEventListener('click',e=>{const b=e.target.closest('[data-id]');if(!b) return;S.idMode=b.dataset.id;commit()});
$('#reset').addEventListener('click',()=>{$('#resetconfirm').hidden=false;$('#reset').hidden=true});
$('#resetno').addEventListener('click',()=>{$('#resetconfirm').hidden=true;$('#reset').hidden=false});
$('#resetyes').addEventListener('click',()=>{S=sample();UI.sel=null;UI.calc=null;$('#resetconfirm').hidden=true;$('#reset').hidden=false;commit()});
$('#hostpick').addEventListener('change',e=>openDoc(e.target.value,undefined,true));
$('#savedesign').addEventListener('click',saveDesign);
$('#versions').addEventListener('click',openVersions);
$('#fromscan').addEventListener('click',()=>openDoc(DOC.host,'scan'));
$('#dropexample').addEventListener('click',()=>{$('#dropconfirm').hidden=false;docState()});
$('#dropno').addEventListener('click',()=>{$('#dropconfirm').hidden=true;docState()});
$('#dropyes').addEventListener('click',()=>setExample(false));
$('#showexample').addEventListener('click',()=>setExample(true));

const view=$('#view');
view.addEventListener('mouseover',e=>{const el=e.target.closest('[data-node]');const id=el?el.dataset.node:null;if(id===UI.hover) return;UI.hover=id;setChain(id)});
view.addEventListener('mouseleave',()=>{UI.hover=null;setChain(null)});
view.addEventListener('focusin',e=>{const el=e.target.closest('[data-node]');if(el){UI.hover=el.dataset.node;setChain(UI.hover)}});
view.addEventListener('keydown',e=>{ if((e.key==='Enter'||e.key===' ')&&e.target.matches('[role=button][data-act]')){e.preventDefault();e.target.click()} });
view.addEventListener('click',e=>{
  if(e.target.closest('input,select,textarea,label.f')) return;
  const a=e.target.closest('[data-act]');if(!a) return;const act=a.dataset.act;
  if(act==='sel'){ e.stopPropagation(); UI.sel={type:a.dataset.type,id:a.dataset.id}; render(); return }
  if(act==='goto'){ if(a.dataset.sel) selectNode(a.dataset.sel); if(a.dataset.sel&&a.dataset.sel.startsWith('mnt:')) UI.mountSel=a.dataset.sel.slice(4); go(a.dataset.v); return }
  if(act==='opt'){ const sc=a.dataset.scope;const o=sc==='part'?selObj():selObj();const arr=o.opts=o.opts||[];const v=a.dataset.opt;const i=arr.indexOf(v);if(i>=0)arr.splice(i,1);else arr.push(v);commit();return }
  if(act==='delsv'){ const p=selObj();p.subvols.splice(+a.dataset.i,1);commit();return }
  if(act==='msel'){ UI.mountSel=a.dataset.t; UI.mountTab='unit'; render(); return }
  if(act==='mtab'){ UI.mountTab=a.dataset.t; render(); return }
  if(act==='etab'){ UI.exportTab=a.dataset.t; render(); return }
  if(act==='stagechanges'){ stageDesignChanges(); return }
  if(act==='preset'){ const p=PRESETS.find(x=>x.id===a.dataset.id);p.links.forEach(x=>{if(!S.links.some(l=>l.path===x.path)) S.links.push({id:'L'+Date.now().toString(36)+Math.random().toString(36).slice(2,5),...x})});commit();return }
  if(act==='dellink'){ S.links=S.links.filter(l=>l.id!==a.dataset.id);commit();return }
  if(['psync','psnap','pval'].includes(act)&&S.protection[+a.dataset.i].deployed){ docState('This row comes from what is deployed or was found by a scan, so it cannot be edited here.','err');return }
  if(act==='offsite'){ const off=!DOC.offsite;apiJSON('/api/planner/offsite',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:DOC.host,offsite:off})}).then(()=>{DOC.offsite=off;render()}).catch(e=>docState(e.message,'err'));return }
  if(act==='psync'){ const r=S.protection[+a.dataset.i];r.sync.state=SYNC_STATES[(SYNC_STATES.indexOf(r.sync.state)+1)%SYNC_STATES.length];if(r.sync.state==='Lagging'&&!r.sync.lag) r.sync.lag='4 h';commit();return }
  if(act==='psnap'){ const r=S.protection[+a.dataset.i];r.snap.on=!r.snap.on;if(r.snap.on&&(!r.snap.tool||r.snap.tool.startsWith('none'))){r.snap.tool=r.node.startsWith('ds:')?'sanoid':'snapper';r.snap.policy='hourly 24 · daily 7'}commit();return }
  if(act==='pval'){ S.protection[+a.dataset.i].backup.last=today();commit();return }
  if(act==='cload'){ const id=a.dataset.id; if(id==='mixed') UI.calc={...defaultCalc(),layout:'btrfs-raid1',sizes:[16e12,16e12,16e12,16e12,12e12,12e12],width:6}; else {const p=poolBy(id);if(p){UI.calc=poolCalc(p);if(p.type==='zfs')UI.calc.recordsize=1048576}} render(); return }
  if(act==='cdel'){ UI.calc.sizes.splice(+a.dataset.i,1); UI.calc.width=Math.min(UI.calc.width,UI.calc.sizes.length)||1; render(); return }
  if(act==='cadd'){ const n=Math.max(1,Math.min(24,+$('#c-addn').value||1));const tb=+$('#c-addtb').value||1;for(let i=0;i<n;i++)UI.calc.sizes.push(tb*1e12); if(UI.calc.layout.startsWith('zfs')&&!UI.calc.layout.endsWith('mirror')) UI.calc.width=UI.calc.sizes.length; render(); return }
  if(act==='copy'){ const pre=document.getElementById(a.dataset.src);const txt=pre.textContent;
    const done=ok=>{a.textContent=ok?'Copied':'Selected · press Ctrl+C';setTimeout(()=>{a.textContent='Copy'},1800)};
    const fallback=()=>{const rg=document.createRange();rg.selectNodeContents(pre);const s=getSelection();s.removeAllRanges();s.addRange(rg);done(false)};
    try{ navigator.clipboard.writeText(txt).then(()=>done(true),fallback) }catch(err){ fallback() } return }
});
view.addEventListener('change',e=>{
  const t=e.target;
  if(t.dataset.c!==undefined){ const c=UI.calc;const k=t.dataset.c;
    if(k==='layout'){c.layout=t.value;if(c.layout.endsWith('mirror'))c.width=2;else c.width=c.sizes.length}
    else if(k==='drive') c.sizes[+t.dataset.i]=Math.max(0.1,+t.value)*1e12;
    else if(k==='width') c.width=Math.max(1,Math.min(c.sizes.length,+t.value||1));
    else if(k==='recordsize'||k==='ashift'||k==='speed') c[k]=+t.value;
    else if(k==='fill') c.fill=Math.max(.05,Math.min(1,(+t.value||70)/100));
    else if(k==='ure') c.ure=+t.value;
    else if(k==='reserve') c.reserve=t.value==='1';
    else if(k==='virt') c.virt=(+t.value||0)*1e12;
    else c[k]=t.value;
    renderSoon();return }
  const f=t.dataset.f;if(!f) return;const o=selObj();if(!o) return;const v=t.value.trim();
  const path=x=>x&&!x.startsWith('/')?'/'+x:x;
  switch(f){
    case 'label':o.label=v;break;
    case 'fs':o.fs=v;o.opts=(OPTS[v]||[]).filter(x=>['noatime','nofail','defaults','sw'].includes(x)).slice(0,2);if(v==='btrfs'&&!o.subvols)o.subvols=[];if(!MOUNTABLE.includes(v))o.mount='';break;
    case 'mount':o.mount=path(v);break;
    case 'svmount':o.subvols[+t.dataset.i].mount=path(v);break;
    case 'newsv':if(v){o.subvols=o.subvols||[];o.subvols.push({name:v.startsWith('@')?v:'@'+v,mount:''})}break;
    case 'customopt':if(v&&!(o.opts=o.opts||[]).includes(v))o.opts.push(v);break;
    case 'table':o.table=v;break;
    case 'tier':o.tier=v;break;
    case 'level':o.level=v;break;
    case 'ashift':o.ashift=+v;break;
    case 'encryption':o.encryption=v;break;
    case 'pmount':o.mount=path(v);break;
    case 'pfs':o.fs=v;o.opts=['noatime','nofail'];break;
    case 'dsmount':o.datasets[+t.dataset.i].mount=path(v);break;
    case 'dsrs':o.datasets[+t.dataset.i].recordsize=v;break;
    case 'dscomp':o.datasets[+t.dataset.i].compression=v;break;
    case 'dssync':o.datasets[+t.dataset.i].sync=v;break;
    case 'newds':if(v&&!o.datasets.some(d=>d.name===v))o.datasets.push({name:v,mount:(o.mount||'/mnt/'+o.name)+'/'+v,recordsize:'128K',compression:'zstd',sync:'standard'});break;
    case 'rstatus':o.status=v;break;
    case 'rmount':o.mount=path(v);break;
  }
  commitSoon();
});
view.addEventListener('submit',e=>{
  if(e.target.id!=='addlink') return;e.preventDefault();
  const kind=$('#nl-kind').value,p=$('#nl-path').value.trim(),t=$('#nl-target').value.trim();
  if(!p.startsWith('/')||!t.startsWith('/')) return;
  S.links.push({id:'L'+Date.now().toString(36),kind,path:p,target:t});commit();
});
let rz;window.addEventListener('resize',()=>{clearTimeout(rz);rz=setTimeout(()=>{if(UI.view==='topology')drawEdges()},120)});
if(document.fonts&&document.fonts.ready) document.fonts.ready.then(()=>{if(UI.view==='topology')drawEdges()});

const {view:h,host:hh}=readHash();if(VIEWS.some(v=>v[0]===h)) UI.view=h;
docState();
// wait for the host list before the first render, so a removed example never flashes up
loadHosts().then(async()=>{
  const want=hh||(!exampleShown()?DOC.hosts[0].host:'');
  if(want&&DOC.signedIn) await openDoc(want);
  if(!DOC.host) render();
  setHash();
  addEventListener('hashchange',async()=>{            // Back, Forward, a typed URL: the view and the design it names
    const r=readHash();
    if(VIEWS.some(v=>v[0]===r.view)&&r.view!==UI.view){ UI.view=r.view; render(); $('#main').scrollTop=0 }
    if(r.host!==DOC.host&&(r.host===''||DOC.hosts.some(x=>x.host===r.host))){ await openDoc(r.host); $('#hostpick').value=DOC.host }
  });
});
