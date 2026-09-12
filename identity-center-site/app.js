(()=>{
  const root=document.documentElement;
  const button=document.getElementById('theme-toggle');
  const key='goreecloud-identity-theme';
  const allowed=['system','light','dark','deep-dark'];
  const labels={system:'System',light:'Light',dark:'Dark','deep-dark':'Deep Dark'};

  function apply(value){
    if(!allowed.includes(value))value='system';
    if(value==='system'){
      root.removeAttribute('data-glz-appearance');
      root.dataset.theme='system';
    }else{
      root.dataset.glzAppearance=value;
      root.dataset.theme=value==='light'?'light':'dark';
    }
    if(button){
      button.textContent=labels[value];
      button.setAttribute('aria-label',`Appearance: ${labels[value]}. Activate to change appearance.`);
    }
    return value;
  }

  let current='system';
  try{current=localStorage.getItem(key)||'system';}catch(_){ }
  current=apply(current);

  if(button)button.addEventListener('click',()=>{
    current=allowed[(allowed.indexOf(current)+1)%allowed.length];
    current=apply(current);
    try{localStorage.setItem(key,current);}catch(_){ }
  });
})();
