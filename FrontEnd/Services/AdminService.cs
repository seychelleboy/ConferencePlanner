using FrontEnd.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FrontEnd.Services
{
    public class AdminService : IAdminService
    {

        private readonly Lazy<long> _creationKey = new Lazy<long>(() => BitConverter.ToInt64(Guid.NewGuid().ToByteArray(), 7));
        
        private readonly IServiceProvider _serviceProvider;
        private bool _adminExists;

        //this will go to the ID db context that you have set up

        public AdminService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public long CreationKey => _creationKey.Value;

        public async Task<bool> AllowAdminUserCreationAsync()
        {
            if (_adminExists)
            {
                return false;
            }
            else
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

                    if (await dbContext.Users.AnyAsync(user => user.IsAdmin))
                    {
                        // There are already admin users so disable admin creation
                        _adminExists = true;
                        return false;
                    }

                    // There are no admin users so enable admin creation
                    return true;
                }

                // There are no admin users so enable admin creation
                
            }

        }
    }
}
