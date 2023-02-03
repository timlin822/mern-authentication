const dateTime=()=>{
    const date=new Date();
    const year=date.getFullYear();
    const month=date.getMonth()+1;
    const day=date.getDate();
    
    const hour=date.getHours();
    const minute=date.getMinutes();
    const second=date.getSeconds();

    const nowDateTime=`${year}-${(month>9?"":"0")}${month}-${(day>9?"":"0")}${day} ${(hour>9?"":"0")}${hour}:${(minute>9?"":"0")}${minute}:${(second>9?"":"0")}${second}`;
    
    return nowDateTime;
};

module.exports=dateTime;