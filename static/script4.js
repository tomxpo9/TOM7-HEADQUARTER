setInterval(()=>{
  const title = document.querySelector('.WHOAMI');
  if(!title) return;
  title.style.opacity = (0.6 + Math.random()*0.2).toString();
}, 400);

setInterval(()=>{
  document.querySelectorAll('.TOOLS-STATUS').forEach(el=>{
      const size = Math.floor(Math.random()*12 + 6);
      el.style.textShadow = `0 0 ${size}px rgba(113, 113, 113, 0.9)`;
  });
}, 700);
