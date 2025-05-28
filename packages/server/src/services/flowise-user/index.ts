import { getDataSource } from '../../DataSource';
import { FlowiseUser } from '../../database/entities/FlowiseUser';
import { DataSource, Repository } from 'typeorm';

class FlowiseUserService {
    private readonly dataSource: DataSource;
    private readonly userRepository: Repository<FlowiseUser>;

    constructor() {
        this.dataSource = getDataSource();
        this.userRepository = this.dataSource.getRepository(FlowiseUser);
    }

    async findOrCreateUserByEmail(email: string): Promise<FlowiseUser> {
        let user = await this.userRepository.findOneBy({ email });
        if (user) {
            return user;
        }
        const newUser = new FlowiseUser();
        newUser.email = email;
        // The createdDate and updatedDate should be handled by TypeORM decorators
        user = await this.userRepository.save(newUser);
        return user;
    }
}

const flowiseUserService = new FlowiseUserService();
export default flowiseUserService;
