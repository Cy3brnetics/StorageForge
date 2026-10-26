'use strict';
const MiB=2**20, GiB=2**30, TiB=2**40;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
      {node:'sv:nvme0n1p2/@home',name:'@home',sync:{state:'Rsync Scheduled',target:'nas-02 nightly 02:30'},snap:{on:true,tool:'snapper',policy:'hourly 12 · daily 14',count:26,overhead:9.1*GiB},backup:{target:'restic → B2',enc:'restic AES-256',ratio:1.4,last:'2026-10-24',offsite:true}},
      {node:'ds:tank/media',name:'tank/media',sync:{state:'Active Sync',target:'syncoid → nas-02/media',lag:'12 min'},snap:{on:true,tool:'sanoid',policy:'daily 30 · monthly 6',count:36,overhead:212*GiB},backup:{target:null,enc:'ZFS native aes-256-gcm',ratio:1.01,last:null,offsite:false}},
      {node:'ds:tank/photos',name:'tank/photos',sync:{state:'Active Sync',target:'syncoid → nas-02/photos',lag:'9 min'},snap:{on:true,tool:'sanoid',policy:'hourly 24 · daily 30 · monthly 12',count:66,overhead:41*GiB},backup:{target:'restic → B2',enc:'ZFS native + restic',ratio:1.03,last:'2026-10-19',offsite:true}},
      {node:'ds:tank/vm',name:'tank/vm',sync:{state:'Lagging',target:'syncoid → nas-02/vm',lag:'6 h 40 min'},snap:{on:true,tool:'sanoid',policy:'frequent 4 · hourly 48',count:52,overhead:380*GiB},backup:{target:'PBS → pbs-02',enc:'PBS AES-256-GCM',ratio:2.3,last:'2026-07-02',offsite:true}},
      {node:'ds:tank/backups',name:'tank/backups',sync:{state:'Active Sync',target:'zfs send → nas-02',lag:'31 min'},snap:{on:true,tool:'sanoid',policy:'daily 14 · weekly 8',count:22,overhead:66*GiB},backup:{target:'age → S3 Glacier IR',enc:'age X25519',ratio:1.0,last:'2026-10-01',offsite:true}},
      {node:'pool:md0',name:'md0 (cold)',sync:{state:'Disconnected',target:'rsync → office-nas'},snap:{on:false,tool:'none (ext4)',policy:'',count:0,overhead:0},backup:{target:null,enc:'LUKS2 (aes-xts-plain64)',ratio:1,last:null,offsite:false}},
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
const DOC={host:'',source:'example',dirty:false,savedAt:null,scanned:false,hosts:[],signedIn:false};
const draftKey=h=>'storageforge.v1'+(h?':'+h:'');
function load(h){ try{ const t=localStorage.getItem(draftKey(h||'')); return t?JSON.parse(t):null }catch(e){ return null } }
function save(){ try{ localStorage.setItem(draftKey(DOC.host),JSON.stringify(S)) }catch(e){} if(DOC.host){DOC.dirty=true;docState()} }
function dropDraft(h){ try{ localStorage.removeItem(draftKey(h)) }catch(e){} }
let S=load('')||sample();

const UI={view:'overview',sel:null,mountSel:'/',mountTab:'fstab',exportTab:'bash',calc:null,hover:null};
const VIEWS=[
  ['overview','Overview','Capacity, protection and every guardrail across the blueprint.'],
  ['devices','Devices','Block devices, partition tables and filesystems. Select a partition, pool or remote to edit it.'],
  ['mounts','Mounts','Mount hierarchy, conflict checks, and the generated /etc/fstab and systemd units.'],
  ['links','Links','Symlinks, bind mounts and hard links, with health checks and boot ordering.'],
  ['topology','Topology','Drives → pools → datasets → mount points → links and exports. Hover a node to trace it.'],
  ['raid','RAID calculator','Usable space, parity, padding, rebuild exposure and write amplification.'],
  ['protection','Protection','3-2-1 matrix: sync, snapshots and offsite backups per dataset.'],
  ['export','Export','Provisioning scripts, units and blueprints generated from this design.']
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
    } else if(pool.mount){
      M.push({target:pool.mount,node:'pool:'+pool.name,kind:'md',fs:pool.fs,opts:pool.opts||[],spec:S.idMode==='LABEL'&&pool.label?'LABEL='+pool.label:'UUID='+fakeUUID(pool.name+'-fs'),dev:'/dev/'+pool.name,pool,tier:pool.tier,desc:`${pool.fs} on mdadm ${pool.level} ${pool.name}`});
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
  if(row.sync.state==='Lagging') why.push(`Replication lagging ${row.sync.lag||''}`.trim());
  if(row.sync.state==='Disconnected') why.push('Replication target unreachable');
  if(row.backup.target&&age>90) why.push(`Backup not validated for ${age} days`);
  const nothing=!row.snap.on&&!row.backup.target&&row.sync.state==='None';
  if(nothing) why.push('Single copy: no snapshots, sync or backup');
  if(badSync||(row.backup.target&&age>90)||nothing||(!row.snap.on&&!row.backup.target)) { if(!why.length) why.push('No snapshots and no backup'); return {k:'crit',t:'Critical',why} }
  if(row.snap.on&&row.backup.target&&row.backup.offsite&&age<=30) return {k:'ok',t:'Protected',why:['Snapshots, offsite backup validated '+(age===0?'today':age+' d ago')]};
  if(!row.backup.target) why.push('No backup target'); else if(!row.backup.offsite) why.push('Backup is not offsite'); else if(age>30) why.push(`Validation ${age} d old`);
  if(!row.snap.on) why.push('No snapshots');
  return {k:'warn',t:'Local only',why};
}
function copies321(row){
  const syncOk=['Active Sync','Rsync Scheduled'].includes(row.sync.state);
  const c=1+(syncOk?1:0)+(row.backup.target?1:0);
  const off=row.backup.offsite||(syncOk&&/nas-02|office|b2|S3/i.test(row.sync.target||''));
  return {c,off};
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
      L.push([m.spec,m.target,m.fs,opts,0,passFor(m)].join('  '));
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
function mkfsCmd(p){
  const L=p.label?p.label:'';const dev='/dev/'+p.id;
  switch(p.fs){
    case 'vfat':return `run mkfs.vfat -F 32 -n ${L.toUpperCase()} ${dev}`;
    case 'ext4':return `run mkfs.ext4 -L ${L} -E lazy_itable_init=0 ${dev}`;
    case 'xfs':return `run mkfs.xfs -f -L ${L} ${dev}`;
    case 'btrfs':return `run mkfs.btrfs -f -L ${L} ${dev}`;
    case 'f2fs':return `run mkfs.f2fs -f -l ${L} -O extra_attr,inode_checksum,sb_checksum,compression ${dev}`;
    case 'swap':return `run mkswap -L ${L} ${dev}`;
  }
  return null;
}
function genBash(){
  const L=[];const M=collectMounts();
  L.push('#!/usr/bin/env bash','# StorageForge provisioning script for host '+S.host+' · generated '+today(),'# Review every step. Runs as a dry run unless DRY_RUN=0 is set.','set -euo pipefail','DRY_RUN="${DRY_RUN:-1}"','run() { if [[ "$DRY_RUN" == 1 ]]; then printf \'[dry-run] %s\\n\' "$*"; else "$@"; fi; }','[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }','');
  L.push('# ── 1. Partition tables ─────────────────────────────────────────');
  S.disks.forEach(d=>{
    if(d.member) return;
    L.push(`# /dev/${d.dev} · ${d.model} · SN ${d.serial} · ${d.bus}`);
    if(d.os){L.push(`#   holds the running root filesystem; partitioned by the installer, verification only`,`run sgdisk --verify /dev/${d.dev}`,'');return}
    L.push(`run wipefs --all /dev/${d.dev}`,`run parted -s -a optimal /dev/${d.dev} mklabel ${d.table==='mbr'?'msdos':'gpt'}`);
    d.parts.forEach(p=>{
      const s=Math.ceil(p.start/MiB),e=Math.floor((p.start+p.size)/MiB);
      const t=p.fs==='zfs_member'?'':p.fs==='linux_raid_member'?'':p.fs==='swap'?'linux-swap':p.fs==='vfat'?'fat32':p.fs;
      L.push(`run parted -s -a optimal /dev/${d.dev} mkpart ${d.table==='mbr'?'primary':p.label||'part'+p.num} ${t} ${s}MiB ${e}MiB`.replace(/  +/g,' '));
      if(p.fs==='linux_raid_member') L.push(`run parted -s /dev/${d.dev} set ${p.num} raid on`);
      if(p.fs==='vfat'&&p.mount==='/boot/efi') L.push(`run parted -s /dev/${d.dev} set ${p.num} esp on`);
      if(p.start%MiB) L.push(`# WARNING: original start ${p.start/512}s was misaligned; recreated at ${s}MiB`);
    });
    L.push('');
  });
  L.push('# ── 2. Filesystems ─────────────────────────────────────────────');
  allParts().forEach(({p,d})=>{ if(d.os) return; const c=mkfsCmd(p); if(c) L.push(c) });
  L.push('');
  const sv=allParts().filter(x=>x.p.fs==='btrfs'&&x.p.subvols&&x.p.subvols.length);
  if(sv.length){L.push('# ── 3. Btrfs subvolumes ────────────────────────────────────────');
    sv.forEach(({p})=>{L.push('run mkdir -p /mnt/.btrfs-top',`run mount -o subvolid=5 /dev/${p.id} /mnt/.btrfs-top`);p.subvols.forEach(s=>L.push(`[[ -d /mnt/.btrfs-top/${s.name} ]] || run btrfs subvolume create /mnt/.btrfs-top/${s.name}`));L.push('run umount /mnt/.btrfs-top')});L.push('')}
  L.push('# ── 4. Arrays and pools ────────────────────────────────────────');
  S.pools.forEach(pool=>{
    const m=poolMembers(pool);
    if(pool.type==='mdadm'){
      L.push(`run mdadm --create /dev/${pool.name} --level=${pool.level.replace('raid','')} --raid-devices=${m.data.length} --metadata=1.2 ${m.data.map(x=>'/dev/'+x.id).join(' ')}`);
      L.push(`run mdadm --detail --scan | tee -a /etc/mdadm/mdadm.conf`);
      L.push(`run mkfs.${pool.fs} ${pool.fs==='ext4'?'-m 1 ':''}-L ${pool.label} /dev/${pool.name}`);
    } else {
      const dev=x=>x.whole?byId(x.disk):'/dev/'+x.id;
      const parts=[`run zpool create -o ashift=${pool.ashift} -O compression=zstd -O atime=off -O xattr=sa -O acltype=posixacl`];
      if(pool.encryption&&pool.encryption!=='off') parts.push(`-O encryption=${pool.encryption} -O keyformat=passphrase -O keylocation=prompt`);
      parts.push(`-m ${pool.mount||'none'} ${pool.name}`);
      parts.push(`${pool.level==='stripe'?'':pool.level} ${m.data.map(dev).join(' ')}`.trim());
      if(m.log.length) parts.push(`log ${m.log.map(dev).join(' ')}`);
      if(m.cache.length) parts.push(`cache ${m.cache.map(dev).join(' ')}`);
      L.push(parts.join(' \\\n    '));
      (pool.datasets||[]).forEach(ds=>L.push(`run zfs create -o recordsize=${ds.recordsize} -o compression=${ds.compression} -o sync=${ds.sync} -o mountpoint=${ds.mount||'none'} ${pool.name}/${ds.name}`));
    }
    L.push('');
  });
  L.push('# ── 5. Mount points and /etc/fstab ─────────────────────────────');
  M.filter(m=>m.kind!=='swap'&&m.kind!=='zfs'&&m.target!=='/').forEach(m=>L.push(`run mkdir -p ${m.target}`));
  L.push("FSTAB_BLOCK=$(cat <<'EOF'",'# BEGIN storageforge',genFstab().split('\n').filter(x=>!x.startsWith('# /etc/fstab')).join('\n'),'# END storageforge','EOF',')');
  L.push('if ! grep -q "# BEGIN storageforge" /etc/fstab; then','  run cp /etc/fstab "/etc/fstab.bak.$(date +%s)"','  if [[ "$DRY_RUN" == 1 ]]; then echo "$FSTAB_BLOCK"; else printf \'%s\\n\' "$FSTAB_BLOCK" >> /etc/fstab; fi','fi','run systemctl daemon-reload','run findmnt --verify','run mount -a','');
  L.push('# ── 6. Links (dependency order) ────────────────────────────────');
  S.links.forEach(l=>{
    const h=linkHealth(l,M);
    if(l.kind==='bind'){L.push(`# bind ${l.target} → ${l.path} is handled by fstab above`+(h.state!=='ok'?`  # ${h.state.toUpperCase()}: ${h.msg}`:''));return}
    if(h.state==='crit'){L.push(`# SKIPPED ${l.kind} ${l.path} → ${l.target}: ${h.msg}`);return}
    L.push(`run mkdir -p "$(dirname '${l.path}')"`);
    L.push(l.kind==='symlink'?`run ln -sfn '${l.target}' '${l.path}'`:`run ln '${l.target}' '${l.path}'`);
  });
  return L.join('\n');
}
function genAnsible(){
  const q=s=>JSON.stringify(String(s));const L=[];const M=collectMounts();
  L.push('---',`# StorageForge playbook for ${S.host} · generated ${today()}`,'# Run with --check --diff first. Requires community.general and ansible.posix.',`- name: Provision storage on ${S.host}`,`  hosts: ${S.host}`,'  become: true','  tasks:');
  S.disks.forEach(d=>{ if(d.member||d.os) return; d.parts.forEach(p=>{
    L.push(`    - name: Partition /dev/${d.dev} p${p.num} (${p.label||p.fs})`,'      community.general.parted:',`        device: /dev/${d.dev}`,`        number: ${p.num}`,`        label: ${d.table==='mbr'?'msdos':'gpt'}`,...(d.table==='gpt'?[`        name: ${q(p.label||'part'+p.num)}`]:[]),`        part_start: ${Math.ceil(p.start/MiB)}MiB`,`        part_end: ${Math.floor((p.start+p.size)/MiB)}MiB`,...(p.fs==='linux_raid_member'?['        flags: [raid]']:[]),'        state: present');
    if(['ext4','xfs','btrfs','f2fs','vfat','swap'].includes(p.fs)) L.push(`    - name: Create ${p.fs} on /dev/${p.id}`,'      community.general.filesystem:',`        fstype: ${p.fs}`,`        dev: /dev/${p.id}`,`        opts: ${q((p.fs==='vfat'?'-n ':p.fs==='f2fs'?'-l ':'-L ')+(p.label||''))}`);
  })});
  S.pools.forEach(pool=>{const m=poolMembers(pool);
    if(pool.type==='mdadm') L.push(`    - name: Create mdadm ${pool.level} ${pool.name}`,`      ansible.builtin.command: mdadm --create /dev/${pool.name} --run --level=${pool.level.replace('raid','')} --raid-devices=${m.data.length} ${m.data.map(x=>'/dev/'+x.id).join(' ')}`,'      args:',`        creates: /dev/${pool.name}`,`    - name: Create ${pool.fs} on /dev/${pool.name}`,'      community.general.filesystem:',`        fstype: ${pool.fs}`,`        dev: /dev/${pool.name}`,`        opts: ${q('-L '+pool.label)}`);
    else{L.push(`    - name: Check for zpool ${pool.name}`,`      ansible.builtin.command: zpool list -H ${pool.name}`,`      register: zp_${pool.name}`,'      changed_when: false','      failed_when: false',`    - name: Create zpool ${pool.name} (${pool.level})`,`      ansible.builtin.command: >-`,`        zpool create -o ashift=${pool.ashift} -O compression=zstd -O atime=off -O xattr=sa -m ${pool.mount||'none'} ${pool.name} ${pool.level==='stripe'?'':pool.level} ${m.data.map(x=>x.whole?byId(x.disk):'/dev/'+x.id).join(' ')}${m.log.length?' log '+m.log.map(x=>'/dev/'+x.id).join(' '):''}${m.cache.length?' cache '+m.cache.map(x=>'/dev/'+x.id).join(' '):''}`,`      when: zp_${pool.name}.rc != 0`);
      (pool.datasets||[]).forEach(ds=>L.push(`    - name: Dataset ${pool.name}/${ds.name}`,'      community.general.zfs:',`        name: ${pool.name}/${ds.name}`,'        state: present','        extra_zfs_properties:',`          recordsize: ${ds.recordsize}`,`          compression: ${ds.compression}`,`          sync: ${ds.sync}`,`          mountpoint: ${ds.mount||'none'}`))}
  });
  M.filter(m=>m.kind!=='zfs'&&m.kind!=='swap').forEach(m=>L.push(`    - name: Mount ${m.target}`,'      ansible.posix.mount:',`        path: ${q(m.target)}`,`        src: ${q(m.spec)}`,`        fstype: ${m.fs}`,`        opts: ${q((m.opts.length?m.opts:['defaults']).join(','))}`,`        state: ${m.opts.includes('x-systemd.automount')?'present':'mounted'}`));
  S.links.filter(l=>l.kind!=='bind').forEach(l=>{const h=linkHealth(l,M);
    if(h.state==='crit'){L.push(`    # skipped ${l.kind} ${l.path}: ${h.msg}`);return}
    L.push(`    - name: ${l.kind} ${l.path}`,'      ansible.builtin.file:',`        src: ${q(l.target)}`,`        dest: ${q(l.path)}`,`        state: ${l.kind==='symlink'?'link':'hard'}`,'        force: false')});
  return L.join('\n');
}
function blueprint(){
  return {apiVersion:'storageforge/v1',kind:'StorageBlueprint',metadata:{host:S.host,generated:today(),identifiers:S.idMode},
    devices:S.disks.map(d=>({dev:'/dev/'+d.dev,model:d.model,serial:d.serial,bus:d.bus,media:d.media,tier:d.tier,sizeBytes:d.size,sector:{logical:d.lbs,physical:d.pbs},table:d.table,member:d.member,
      partitions:d.parts.map(p=>({id:p.id,num:p.num,uuid:p.uuid,startBytes:p.start,startMiB:+(p.start/MiB).toFixed(3),sizeBytes:p.size,fs:p.fs,label:p.label,mount:p.mount,options:p.opts,member:p.member,role:p.role,subvolumes:p.subvols}))})),
    pools:S.pools.map(p=>({name:p.name,type:p.type,level:p.level,tier:p.tier,ashift:p.ashift,fs:p.fs,mount:p.mount,encryption:p.encryption,members:poolMembers(p).data.map(x=>x.id),log:poolMembers(p).log.map(x=>x.id),cache:poolMembers(p).cache.map(x=>x.id),datasets:p.datasets,label:p.label,options:p.opts,usableBytes:Math.round(calcEngine(poolCalc(p)).usable)})),
    mounts:collectMounts().map(m=>({target:m.target,kind:m.kind,fs:m.fs,spec:m.spec,options:m.opts,tier:m.tier,source:m.dev})),
    remotes:S.remotes.map(r=>({id:r.id,capacity:r.capacity,name:r.name,protocol:r.proto,endpoint:r.endpoint,via:r.via,mount:r.mount,status:r.status,options:r.opts})),
    links:S.links.map(l=>({kind:l.kind,path:l.path,target:l.target,health:linkHealth(l).state,fromScan:l.fromScan||undefined})),
    exports:S.exports.map(e=>({protocol:e.proto,name:e.name,path:e.path,clients:e.clients,options:e.opts})),
    protection:S.protection.map(r=>{const m=collectMounts().find(x=>x.node===r.node)||{};return {node:r.node,dataset:r.name,path:m.target||null,tier:m.tier||null,ephemeral:!!r.ephemeral,sync:r.sync,snapshots:{enabled:r.snap.on,tool:r.snap.tool,policy:r.snap.policy,count:r.snap.count,overhead:r.snap.overhead},backup:r.backup,status:protStatus(r).t}}),
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
      const dc=d.member?[{t:`whole disk → zpool ${d.member}`}]:d.parts.map(p=>{
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
function render(){
  nav();
  const v=VIEWS.find(x=>x[0]===UI.view);$('#vt').textContent=v[1];$('#vs').textContent=v[2];
  const fn={overview:vOverview,devices:vDevices,mounts:vMounts,links:vLinks,topology:vTopology,raid:vRaid,protection:vProtection,export:vExport}[UI.view];
  $('#view').innerHTML=fn();
  if(UI.view==='topology') requestAnimationFrame(drawEdges);
  setChain(null);
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
  const mass=[...S.pools.filter(p=>p.tier==='mass').map(p=>{const r=calcEngine(poolCalc(p));const m=poolMembers(p);return it('pool:'+p.name,`${p.name} · ${p.type} ${p.level}`,`${m.data.length}× ${esc(m.data[0]?m.data[0].disk.model.split(' (')[0]:'')} · tolerates ${r.tol}`,fmtBin(r.usable)+'<br><span class="muted">usable</span>')}),
    ...allParts().filter(x=>x.d.tier==='mass'&&!x.p.member).map(({p,d})=>it('part:'+p.id,'/dev/'+p.id,esc(partRole(p))+' · no redundancy',fmtBin(p.size)))];
  const remote=[...allParts().filter(x=>x.d.tier==='remote').map(({p,d})=>it('part:'+p.id,'/dev/'+p.id,`${esc(d.bus)} · ${esc(partRole(p))}`,fmtBin(p.size))),
    ...S.remotes.map(r=>it('rem:'+r.id,`<span class="dot ${r.status==='connected'?'ok':'crit'}"></span>${esc(r.name)}`,`${esc(r.proto)} via ${esc(r.via)} → ${esc(r.mount)}`,r.capacity?fmtDec(r.capacity,0):'metered'))];
  return tiles+`<div class="grid" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);align-items:start" id="ovgrid">${alerts}<div class="stack">${tierCard('fast','Fast local tier',fast)}${tierCard('mass','Mass local tier',mass)}${tierCard('remote','Remote / mesh targets',remote)}</div></div>
  `;
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
  if(d.member){segs=`<button type="button" class="seg fs-zfs_member" style="flex-grow:1" data-node="disk:${d.dev}" data-act="sel" data-type="pool" data-id="${esc(d.member)}"><b>whole disk · zfs member</b><span>→ ${esc(d.member)} · partitions p1/p9 created by zpool</span></button>`}
  else{
    let cur=0;const parts=d.parts.slice().sort((a,b)=>a.start-b.start);const limit=d.table==='mbr'?Math.min(d.size,2*TiB):d.size;
    parts.forEach(p=>{ if(p.start-cur>=64*MiB) segs+=`<div class="seg free" style="flex-grow:${(p.start-cur)/d.size}"><b>free</b><span>${fmtBin(p.start-cur,1)}</span></div>`; segs+=segHTML(d,p); cur=p.start+p.size });
    if(limit-cur>=64*MiB) segs+=`<div class="seg free" style="flex-grow:${(limit-cur)/d.size}"><b>unallocated</b><span>${fmtBin(limit-cur,1)}</span></div>`;
    if(d.table==='mbr'&&d.size>2*TiB) segs+=`<div class="seg dead" style="flex-grow:${(d.size-2*TiB)/d.size}"><b>beyond MBR limit</b><span>${fmtBin(d.size-2*TiB,1)} unaddressable</span></div>`;
  }
  const sect=d.lbs===d.pbs?(d.pbs===4096?'4Kn':'512n'):'512e';
  return `<article class="disk ${d.tier} ${sel?'sel':''}" data-node="disk:${esc(d.dev)}" data-act="sel" data-type="disk" data-id="${esc(d.dev)}">
    <div class="dh"><span class="dev">/dev/${esc(d.dev)}</span><span class="chip t-${d.tier}">${esc(d.bus)}</span><span class="chip">${d.table.toUpperCase()}</span><span class="chip">${sect} · ${d.lbs}/${d.pbs}</span>${d.os?'<span class="chip">boot</span>':''}<span class="sz">${both(d.size)}</span></div>
    <div class="dmeta">${esc(d.model)} · SN ${esc(d.serial)}</div>
    <div class="pbar">${segs}</div></article>`;
}
function poolHTML(p){
  const sel=UI.sel&&UI.sel.type==='pool'&&UI.sel.id===p.name;const m=poolMembers(p);const r=calcEngine(poolCalc(p));
  const rows=p.type==='zfs'?(p.datasets||[]).map(ds=>`<div class="dsrow" data-node="ds:${esc(p.name)}/${esc(ds.name)}"><span>${esc(p.name)}/${esc(ds.name)}</span><span class="muted">${esc(ds.mount||'—')}</span><span class="muted">rs=${esc(ds.recordsize)} ${esc(ds.compression)}${ds.sync!=='standard'?' sync='+esc(ds.sync):''}</span></div>`).join(''):`<div class="dsrow"><span>${esc(p.fs)} · ${esc(p.label)}</span><span class="muted">${esc(p.mount)}</span><span class="muted">${esc((p.opts||[]).join(','))}</span></div>`;
  return `<article class="pool ${sel?'sel':''}" data-node="pool:${esc(p.name)}" data-act="sel" data-type="pool" data-id="${esc(p.name)}">
    <div class="dh"><span class="dev">${esc(p.name)}</span><span class="chip t-${p.tier}">${p.type==='zfs'?'OpenZFS':'mdadm'} ${esc(p.level)}</span>${p.type==='zfs'?`<span class="chip">ashift=${p.ashift}</span><span class="chip">${p.encryption==='off'?'unencrypted':esc(p.encryption)}</span>`:''}<span class="sz">${fmtBin(r.usable)} usable · tolerates ${r.tol}</span></div>
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
    return `<div class="ph"><h2>${esc(p.name)}</h2><span class="sub">${p.type==='zfs'?'OpenZFS pool':'mdadm array'}</span></div><div class="pb">
      <div class="fields">
        <label class="f">Level<select id="i-level" data-f="level">${(p.type==='zfs'?['stripe','mirror','raidz1','raidz2','raidz3']:['raid0','raid1','raid5','raid6','raid10']).map(l=>`<option ${l===p.level?'selected':''}>${l}</option>`).join('')}</select></label>
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
    rows.push(`<div class="trow ${UI.mountSel===m.target?'sel':''}" style="--d:${d}" data-node="${esc(m.node)}" data-act="msel" data-t="${esc(m.target)}" tabindex="0" role="button"><span class="p">${head}</span><span class="s">${esc(m.spec)}${m.kind==='subvol'?'':''} · ${esc(m.opts.join(',')||'defaults')}</span><span class="c"><span class="chip t-${m.tier}">${esc(m.kind==='bind'?'bind':m.fs)}</span>${flags(m)}</span></div>`);
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
    return `<tr data-node="link:${esc(l.id)}"><td><span class="kind ${l.kind}">${l.kind}</span></td><td class="lk">${esc(l.path)}</td><td class="arrow">${l.kind==='bind'?'⇇':l.kind==='hardlink'?'⇔':'→'}</td><td class="lk">${esc(l.target)}</td>
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
  S.links.forEach(l=>{const h=linkHealth(l,M);col4.push(tn('link:'+l.id,esc(l.path),`${l.kind} → ${esc(l.target)}`,h.state!=='ok'?'bad':'',`style="--tc:var(--${h.state==='ok'?'ok':h.state})"`))});
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
      <td><b class="mono">${esc(r.name)}</b><div class="muted mono" style="font-size:11.5px">${esc(path)}</div></td>
      <td><div class="pcell" data-act="psync" data-i="${i}" role="button" tabindex="0" title="Click to cycle sync state"><span class="st ${sk}">${esc(r.sync.state)}</span><small>${esc(r.sync.target||'no replication')}${r.sync.lag?' · lag '+esc(r.sync.lag):''}</small></div></td>
      <td><div class="pcell" data-act="psnap" data-i="${i}" role="button" tabindex="0" title="Click to toggle snapshots"><span class="st ${r.snap.on?'ok':'crit'}">${r.snap.on?esc(r.snap.tool):'No snapshots'}</span><small>${r.snap.on?`${esc(r.snap.policy)} · ${r.snap.count} kept · ${fmtBin(r.snap.overhead,1)}`:'click to enable'}</small></div></td>
      <td><span class="st ${r.backup.target?(r.backup.offsite?'ok':'warn'):'crit'}">${esc(r.backup.target||'No backup')}</span><div class="muted mono" style="font-size:11px">${r.backup.target?`${r.backup.offsite?'offsite':'same site'} · ${r.backup.ratio.toFixed(2)}× compression`:''}</div></td>
      <td class="mono" style="font-size:11.5px">${esc(r.backup.enc)}</td>
      <td>${r.backup.target?`<span class="st ${age>90?'crit':age>30?'warn':'ok'} num">${esc(r.backup.last)}</span><div class="muted" style="font-size:11px">${age} days ago</div><button type="button" class="btn sm ghost" style="margin-top:4px" data-act="pval" data-i="${i}">Mark validated</button>`:'<span class="muted">—</span>'}</td>
      <td class="num mono" style="font-size:12px">${c.c} cop${c.c>1?'ies':'y'}<br><span class="muted">${c.off?'offsite ✓':'no offsite'}</span></td>
      <td><span class="pill ${st.k}">${st.t}</span><div class="why">${esc(st.why.join(' · '))}</div></td></tr>`}).join('');
  const P=S.protection.map(protStatus);
  return `<div class="grid g4">${[['ok','Protected','Snapshots plus a validated offsite copy'],['warn','Local only','A copy is missing, stale or on the same site'],['crit','Critical','Stale sync, unvalidated backup or a single copy'],['muted','Excluded','Ephemeral scratch, not tracked']].map(([k,t,d])=>`<div class="panel kpi"><span class="pill ${k}">${t}</span><span class="v">${P.filter(x=>x.k===k).length}</span><span class="s">${d}</span></div>`).join('')}</div>
  <section class="panel"><div class="ph"><h2>3-2-1 health grid</h2><span class="sub">Click a sync or snapshot cell to simulate a state change</span></div>
  <div class="tw"><table style="min-width:1080px"><thead><tr><th>Dataset</th><th>Synced</th><th>Snapshots</th><th>Backup</th><th>Encryption</th><th>Last validated</th><th>3-2-1</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
}

/* export */
const EXPORTS=[['bash','Bash script'],['ansible','Ansible playbook'],['units','systemd units'],['fstab','/etc/fstab'],['json','Blueprint JSON'],['yaml','Blueprint YAML'],['ascii','ASCII tree']];
function vExport(){
  const t=UI.exportTab;
  const code={bash:genBash,ansible:genAnsible,units:genUnits,fstab:genFstab,json:()=>JSON.stringify(blueprint(),null,2),yaml:()=>'# StorageForge blueprint'+toYAML(blueprint()),ascii:genASCII}[t]();
  const A=analyze().filter(a=>a.sev==='crit');
  return `${A.length?`<div class="note crit"><b>${A.length} critical issue${A.length>1?'s':''} in this blueprint.</b> The scripts skip broken links and comment them out, but misalignment, duplicate mounts and stale backups carry through. Review the Overview before running.</div>`:''}
  <section class="panel"><div class="ph"><div class="tabs" role="tablist">${EXPORTS.map(([k,l])=>`<button type="button" role="tab" class="${k===t?'on':''}" data-act="etab" data-t="${k}">${l}</button>`).join('')}</div>
  <div class="row"><span class="muted" style="font-size:12px">${code.split('\n').length} lines</span><button type="button" class="btn sm pri" data-act="copy" data-src="ecode">Copy</button></div></div>
  <pre class="code" id="ecode" style="max-height:none">${t==='json'?esc(code):hl(code)}</pre></section>`;
}

/* ───────────── blueprint → planner model ───────────── */
function fromBlueprint(bp){
  const md=bp.metadata||{};const bare=x=>String(x||'').replace(/^\/dev\//,'');
  const s={host:md.host||'host',idMode:md.identifiers==='LABEL'?'LABEL':'UUID',
    disks:(bp.devices||[]).map(d=>({dev:bare(d.dev),model:d.model||'unknown model',serial:d.serial||'—',bus:d.bus||'unknown bus',media:d.media||'hdd',
      size:d.sizeBytes||0,lbs:(d.sector||{}).logical||512,pbs:(d.sector||{}).physical||4096,table:d.table||'gpt',tier:d.tier||'mass',member:d.member||undefined,
      parts:(d.partitions||[]).map((p,i)=>({id:p.id,num:p.num||i+1,uuid:p.uuid||undefined,start:p.startBytes!=null?p.startBytes:Math.round((p.startMiB||0)*MiB),size:p.sizeBytes||0,
        fs:p.fs||'none',label:p.label||'',mount:p.mount||undefined,opts:p.options||[],member:p.member||undefined,role:p.role||undefined,
        subvols:p.subvolumes&&p.subvolumes.length?p.subvolumes.map(v=>({name:v.name,mount:v.mount||undefined})):undefined}))})),
    pools:(bp.pools||[]).map(p=>({name:p.name,type:p.type||'mdadm',level:p.level||'stripe',ashift:p.ashift||12,tier:p.tier||'mass',encryption:p.encryption||undefined,
      mount:p.mount||undefined,fs:p.fs||undefined,label:p.label||undefined,opts:p.options||undefined,datasets:(p.datasets||[]).map(ds=>({...ds}))})),
    remotes:(bp.remotes||[]).map((r,i)=>({id:r.id||'r'+i,name:r.name||r.endpoint,proto:r.protocol||'NFSv4.2',endpoint:r.endpoint||'',via:r.via||'network',
      mount:r.mount||undefined,status:r.status||'connected',capacity:r.capacity??null,opts:r.options||['_netdev','nofail']})),
    links:(bp.links||[]).map((l,i)=>({id:'L'+i,kind:l.kind,path:l.path,target:l.target,fromScan:l.fromScan||undefined})),
    exports:(bp.exports||[]).map((e,i)=>({id:'e'+i,proto:e.protocol||e.proto,name:e.name,path:e.path,clients:e.clients||'',opts:e.options||e.opts||''})),
    existing:(bp.planner||{}).existing||{},known:(bp.planner||{}).known||[],
    protection:(bp.protection||[]).map(r=>{const sn=r.snapshots||r.snap||{};const b=r.backup||{};
      return {node:r.node||nodeForPath(bp,r.path),name:r.dataset||r.name||r.path||'?',ephemeral:!!r.ephemeral,sync:{state:'None',...(r.sync||{})},
        snap:{on:!!(sn.enabled??sn.on),tool:sn.tool||'none',policy:sn.policy||'',count:sn.count||0,overhead:sn.overhead||0},
        backup:{target:b.target||null,enc:b.enc||'none',ratio:b.ratio||1,last:b.last||null,offsite:!!b.offsite}}})};
  // whole-disk members are recorded per pool in the blueprint; the planner keeps them on the disk
  (bp.pools||[]).forEach(p=>(p.members||[]).map(bare).forEach(m=>{const d=s.disks.find(x=>x.dev===m);if(d&&!d.parts.some(x=>x.id===m)) d.member=p.name}));
  return s;
}
function nodeForPath(bp,path){ const S0=S;try{ S=fromBlueprint({...bp,protection:[]});const m=collectMounts().find(x=>x.target===path);return m?m.node:'path:'+path }finally{ S=S0 } }

/* ───────────── server: hosts, load, save ───────────── */
async function apiJSON(path,opts={}){
  const r=await fetch(path,{credentials:'same-origin',...opts});
  if(r.status===401){DOC.signedIn=false;$('#signin').hidden=false;throw new Error('Sign in required')}
  const j=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.error||r.statusText);
  return j;
}
function docState(msg,cls){
  const el=$('#docstate');el.className=cls||(DOC.dirty?'dirty':'muted');
  el.textContent=msg||(!DOC.host?'Example design. Edits stay in this browser.'
    :DOC.dirty?'Unsaved changes (kept in this browser).'
    :DOC.source==='scan'?'Built from the latest scan. Save it to keep your design.'
    :'Saved design · '+new Date(DOC.savedAt*1000).toLocaleString());
  $('#savedesign').hidden=!DOC.host||!DOC.signedIn;$('#fromscan').hidden=!DOC.host||!DOC.scanned||!DOC.signedIn;
  $('#reset').hidden=!!DOC.host;$('#hostpick').value=DOC.host;
}
async function loadHosts(){
  try{
    const {hosts}=await apiJSON('/api/planner/hosts');DOC.signedIn=true;DOC.hosts=hosts;$('#signin').hidden=true;
    const sel=$('#hostpick');
    sel.replaceChildren(new Option('Example host “atlas”',''),...hosts.map(h=>new Option(`${h.host}${h.saved?' · saved':''}${h.scanned?' · scanned':''}`,h.host)));
    sel.value=DOC.host;
  }catch(e){ /* signed out: the example still works */ }
}
async function openDoc(host,source){
  if(DOC.host&&DOC.dirty&&!confirm(`Leave ${DOC.host} with unsaved changes? They stay as a draft in this browser.`)){ $('#hostpick').value=DOC.host;return }
  if(!host){ DOC.host='';DOC.source='example';DOC.dirty=false;S=load('')||sample();UI.sel=null;UI.calc=null;render();docState();setHash();return }
  docState('Loading '+host+'…');
  try{
    const r=await apiJSON('/api/planner/design?host='+encodeURIComponent(host)+(source?'&source='+source:''));
    const draft=!source&&load(host);
    Object.assign(DOC,{host,source:r.source,savedAt:r.saved_at,scanned:r.scanned,dirty:!!draft});
    S=draft||fromBlueprint(r.blueprint);if(!source) normalizeIds();UI.sel=null;UI.calc=null;render();docState();setHash();
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
function setHash(){ try{ history.replaceState(null,'','#'+UI.view+(DOC.host?'@'+encodeURIComponent(DOC.host):'')) }catch(e){} }

/* ───────────── events ───────────── */
function selObj(){
  const s=UI.sel;if(!s) return null;
  if(s.type==='part') return findPart(s.id)?.p;
  if(s.type==='pool') return poolBy(s.id);
  if(s.type==='disk') return diskBy(s.id);
  if(s.type==='rem') return remoteBy(s.id);
}
function commit(){ save(); render(); }
function selectNode(node){
  const [t,...r]=node.split(':');const v=r.join(':');
  if(t==='part') UI.sel={type:'part',id:v};
  else if(t==='sv') UI.sel={type:'part',id:v.split('/')[0]};
  else if(t==='disk') UI.sel={type:'disk',id:v};
  else if(t==='pool') UI.sel={type:'pool',id:v};
  else if(t==='ds') UI.sel={type:'pool',id:v.split('/')[0]};
  else if(t==='rem') UI.sel={type:'rem',id:v};
}
function go(view){ UI.view=view; setHash(); render(); $('#main').scrollTop=0; }
$('#nav').addEventListener('click',e=>{const b=e.target.closest('[data-view]');if(b) go(b.dataset.view)});
$('#idmode').addEventListener('click',e=>{const b=e.target.closest('[data-id]');if(!b) return;S.idMode=b.dataset.id;commit()});
$('#reset').addEventListener('click',()=>{$('#resetconfirm').hidden=false;$('#reset').hidden=true});
$('#resetno').addEventListener('click',()=>{$('#resetconfirm').hidden=true;$('#reset').hidden=false});
$('#resetyes').addEventListener('click',()=>{S=sample();UI.sel=null;UI.calc=null;$('#resetconfirm').hidden=true;$('#reset').hidden=false;commit()});
$('#hostpick').addEventListener('change',e=>openDoc(e.target.value));
$('#savedesign').addEventListener('click',saveDesign);
$('#fromscan').addEventListener('click',()=>openDoc(DOC.host,'scan'));

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
  if(act==='preset'){ const p=PRESETS.find(x=>x.id===a.dataset.id);p.links.forEach(x=>{if(!S.links.some(l=>l.path===x.path)) S.links.push({id:'L'+Date.now().toString(36)+Math.random().toString(36).slice(2,5),...x})});commit();return }
  if(act==='dellink'){ S.links=S.links.filter(l=>l.id!==a.dataset.id);commit();return }
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
    render();return }
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
  commit();
});
view.addEventListener('submit',e=>{
  if(e.target.id!=='addlink') return;e.preventDefault();
  const kind=$('#nl-kind').value,p=$('#nl-path').value.trim(),t=$('#nl-target').value.trim();
  if(!p.startsWith('/')||!t.startsWith('/')) return;
  S.links.push({id:'L'+Date.now().toString(36),kind,path:p,target:t});commit();
});
let rz;window.addEventListener('resize',()=>{clearTimeout(rz);rz=setTimeout(()=>{if(UI.view==='topology')drawEdges()},120)});
if(document.fonts&&document.fonts.ready) document.fonts.ready.then(()=>{if(UI.view==='topology')drawEdges()});

const [h,hh]=(location.hash||'').slice(1).split('@');if(VIEWS.some(v=>v[0]===h)) UI.view=h;
render();docState();
loadHosts().then(()=>{ const want=decodeURIComponent(hh||''); if(want&&DOC.signedIn) openDoc(want) });
