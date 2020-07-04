/**
 * DEFINE YOUR OWN CLAIM MAPPING HERE
 * TO BE PUT IN AAC CONFIG OF NIFI CLIENT APP
**/
function claimMapping(claims) {
    // extract roles
    var path = 'components/nifi/';
    if(claims.roles && claims.roles != null && claims.roles != undefined){
        var roles = claims.roles.filter(function(r) {
                return r.indexOf(path) == 0;
            })
            .map(function(r) {
                var subrole = r.substring(path.length);
                var a = subrole.split(':');
                return {
                    org: a[0].replace(/\//g, '_').replace(/\./g, '_'),
                    role: a[1]
                }
            })
            .reduce(function(prev, curr) { 
    	    // the categories of roles in NiFi
                if(curr.role === 'ROLE_MANAGER')
                    prev[curr.org] = 'ROLE_MANAGER';
                if(!prev[curr.org])
                    prev[curr.org] = 'ROLE_MONITOR';
                
                return prev;
            }, {});
        claims['nifi/roles'] = roles;
    }
    return claims;
}
